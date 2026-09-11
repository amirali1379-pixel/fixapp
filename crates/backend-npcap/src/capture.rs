use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureDirection {
    Inbound,
    Outbound,
    InboundAndOutbound,
}

impl Default for CaptureDirection {
    fn default() -> Self {
        Self::InboundAndOutbound
    }
}

impl CaptureDirection {
    fn as_pcap_direction(self) -> crate::ffi::PcapDirection {
        match self {
            Self::Inbound => crate::ffi::PcapDirection::In,
            Self::Outbound => crate::ffi::PcapDirection::Out,
            Self::InboundAndOutbound => crate::ffi::PcapDirection::InOut,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureState {
    Stopped,
    Starting,
    Running,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedPacket {
    pub data: Vec<u8>,
    /// Native Npcap wall-clock timestamp.
    ///
    /// This remains separate from `network_core::Timestamp`, which is
    /// monotonic and is assigned at the engine ingestion boundary.
    pub timestamp: SystemTime,
    pub interface_index: u32,
    pub original_length: usize,
}

impl CapturedPacket {
    pub fn new(
        data: Vec<u8>,
        interface_index: u32,
    ) -> Option<Self> {
        if data.is_empty() || interface_index == 0 {
            return None;
        }

        let original_length = data.len();

        Some(Self {
            data,
            timestamp: SystemTime::now(),
            interface_index,
            original_length,
        })
    }

    pub fn with_original_length(
        data: Vec<u8>,
        interface_index: u32,
        original_length: usize,
    ) -> Option<Self> {
        if data.is_empty()
            || interface_index == 0
            || original_length < data.len()
        {
            return None;
        }

        Some(Self {
            data,
            timestamp: SystemTime::now(),
            interface_index,
            original_length,
        })
    }

    pub(crate) fn from_pcap(
        data: Vec<u8>,
        interface_index: u32,
        original_length: usize,
        timestamp: SystemTime,
    ) -> Option<Self> {
        if data.is_empty()
            || interface_index == 0
            || original_length < data.len()
        {
            return None;
        }

        Some(Self {
            data,
            timestamp,
            interface_index,
            original_length,
        })
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureConfig {
    pub interface_index: u32,
    pub snaplen: usize,
    pub promiscuous: bool,
    pub direction: CaptureDirection,
    pub timeout_ms: i32,
}

impl CaptureConfig {
    pub fn new(
        interface_index: u32,
    ) -> Option<Self> {
        if interface_index == 0 {
            return None;
        }

        Some(Self {
            interface_index,
            snaplen: 65_535,
            promiscuous: true,
            direction: CaptureDirection::InboundAndOutbound,
            timeout_ms: 1_000,
        })
    }

    pub fn validate(&self) -> bool {
        self.interface_index != 0
            && self.snaplen > 0
            && self.snaplen <= 65_535
            && self.timeout_ms >= 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureError {
    InvalidConfiguration,
    AlreadyRunning,
    NotRunning,
    InterfaceUnavailable,
    ReceiveFailed,
    InvalidPacket,
}

#[derive(Debug)]
pub struct CaptureSession {
    config: CaptureConfig,
    state: CaptureState,
    packets_received: u64,
    bytes_received: u64,
    handle: Option<*mut crate::ffi::PcapT>,
}

// SAFETY: the native handle is owned exclusively by this session.
// Access to the handle is serialized through `&mut self`.
unsafe impl Send for CaptureSession {}

impl CaptureSession {
    pub fn new(
        config: CaptureConfig,
    ) -> Result<Self, CaptureError> {
        if !config.validate() {
            return Err(
                CaptureError::InvalidConfiguration
            );
        }

        Ok(Self {
            config,
            state: CaptureState::Stopped,
            packets_received: 0,
            bytes_received: 0,
            handle: None,
        })
    }

    /// Opens the native Npcap device and starts the capture.
    pub fn start(
        &mut self,
        device_name: &str,
    ) -> Result<(), CaptureError> {
        if self.state == CaptureState::Running {
            return Err(
                CaptureError::AlreadyRunning
            );
        }

        if !self.config.validate() {
            self.state = CaptureState::Failed;

            return Err(
                CaptureError::InvalidConfiguration
            );
        }

        if device_name.trim().is_empty() {
            self.state = CaptureState::Failed;

            return Err(
                CaptureError::InterfaceUnavailable
            );
        }

        self.state = CaptureState::Starting;

        #[cfg(windows)]
        {
            match open_native_handle(
                device_name,
                &self.config,
            ) {
                Ok(handle) => {
                    self.handle = Some(handle);
                    self.state = CaptureState::Running;

                    Ok(())
                }

                Err(error) => {
                    self.handle = None;
                    self.state = CaptureState::Failed;

                    Err(error)
                }
            }
        }

        #[cfg(not(windows))]
        {
            let _ = device_name;

            self.handle = None;
            self.state = CaptureState::Running;

            Ok(())
        }
    }

    pub fn stop(
        &mut self,
    ) -> Result<(), CaptureError> {
        if self.state != CaptureState::Running {
            return Err(
                CaptureError::NotRunning
            );
        }

        self.close_native_handle();
        self.state = CaptureState::Stopped;

        Ok(())
    }

    #[cfg(windows)]
    pub fn receive_packet(
        &mut self,
    ) -> Result<Option<CapturedPacket>, CaptureError> {
        if !self.is_running() {
            return Err(CaptureError::NotRunning);
        }

        let handle = self
            .handle
            .ok_or(CaptureError::NotRunning)?;

        let mut header:
            *mut crate::ffi::PcapPkthdr =
            std::ptr::null_mut();

        let mut data:
            *mut std::os::raw::c_uchar =
            std::ptr::null_mut();

        let result = unsafe {
            crate::ffi::pcap_next_ex(
                handle,
                &mut header,
                &mut data,
            )
        };

        match crate::ffi::PcapReceiveStatus::from_raw(result) {
            crate::ffi::PcapReceiveStatus::Packet => {
                if header.is_null() || data.is_null() {
                    self.state = CaptureState::Failed;
                    self.close_native_handle();

                    return Err(
                        CaptureError::ReceiveFailed
                    );
                }

                let header_value =
                    unsafe { *header };

                let (caplen, original_length) =
                    crate::ffi::validate_packet_header(
                        &header_value,
                    )
                    .map_err(|_| {
                        CaptureError::InvalidPacket
                    })?;

                if caplen > self.config.snaplen {
                    return Err(
                        CaptureError::InvalidPacket
                    );
                }

                let bytes = unsafe {
                    std::slice::from_raw_parts(
                        data,
                        caplen,
                    )
                }
                .to_vec();

                let timestamp =
                    crate::ffi::pcap_timestamp_to_system_time(
                        &header_value,
                    )
                    .ok_or(
                        CaptureError::InvalidPacket
                    )?;

                let packet =
                    CapturedPacket::from_pcap(
                        bytes,
                        self.config.interface_index,
                        original_length,
                        timestamp,
                    )
                    .ok_or(
                        CaptureError::InvalidPacket
                    )?;

                self.record_packet(&packet)?;

                Ok(Some(packet))
            }

            crate::ffi::PcapReceiveStatus::Timeout => {
                Ok(None)
            }

            crate::ffi::PcapReceiveStatus::EndOfCapture
            | crate::ffi::PcapReceiveStatus::Error => {
                self.state = CaptureState::Failed;
                self.close_native_handle();

                Err(
                    CaptureError::ReceiveFailed
                )
            }
        }
    }

    #[cfg(not(windows))]
    pub fn receive_packet(
        &mut self,
    ) -> Result<Option<CapturedPacket>, CaptureError> {
        if !self.is_running() {
            return Err(CaptureError::NotRunning);
        }

        Ok(None)
    }

    pub fn state(&self) -> CaptureState {
        self.state
    }

    pub fn is_running(&self) -> bool {
        self.state == CaptureState::Running
    }

    pub fn config(&self) -> &CaptureConfig {
        &self.config
    }

    pub fn packets_received(&self) -> u64 {
        self.packets_received
    }

    pub fn bytes_received(&self) -> u64 {
        self.bytes_received
    }

    pub fn record_packet(
        &mut self,
        packet: &CapturedPacket,
    ) -> Result<(), CaptureError> {
        if !self.is_running() {
            return Err(
                CaptureError::NotRunning
            );
        }

        if packet.is_empty()
            || packet.interface_index
                != self.config.interface_index
            || packet.original_length < packet.len()
            || packet.len() > self.config.snaplen
        {
            return Err(
                CaptureError::InvalidPacket
            );
        }

        self.packets_received =
            self.packets_received.saturating_add(1);

        self.bytes_received =
            self.bytes_received.saturating_add(
                packet.len() as u64
            );

        Ok(())
    }

    pub fn reset_statistics(&mut self) {
        self.packets_received = 0;
        self.bytes_received = 0;
    }

    fn close_native_handle(&mut self) {
        if let Some(handle) = self.handle.take() {
            #[cfg(windows)]
            unsafe {
                crate::ffi::pcap_close(handle);
            }

            #[cfg(not(windows))]
            {
                let _ = handle;
            }
        }
    }
}

impl Drop for CaptureSession {
    fn drop(&mut self) {
        self.close_native_handle();
        self.state = CaptureState::Stopped;
    }
}

#[cfg(windows)]
fn open_native_handle(
    device_name: &str,
    config: &CaptureConfig,
) -> Result<*mut crate::ffi::PcapT, CaptureError> {
    use std::ffi::CString;

    let device = CString::new(device_name)
        .map_err(|_| CaptureError::InterfaceUnavailable)?;

    let mut errbuf =
        [0 as std::os::raw::c_char;
            crate::ffi::PCAP_ERRBUF_SIZE];

    let snaplen =
        i32::try_from(config.snaplen)
            .map_err(|_| {
                CaptureError::InvalidConfiguration
            })?;

    if snaplen <= 0 {
        return Err(
            CaptureError::InvalidConfiguration
        );
    }

    let handle = unsafe {
        crate::ffi::pcap_open_live(
            device.as_ptr(),
            snaplen,
            if config.promiscuous {
                1
            } else {
                0
            },
            config.timeout_ms,
            errbuf.as_mut_ptr(),
        )
    };

    if handle.is_null() {
        return Err(
            CaptureError::InterfaceUnavailable
        );
    }

    let direction_status = unsafe {
        crate::ffi::pcap_setdirection(
            handle,
            config
                .direction
                .as_pcap_direction()
                .as_raw(),
        )
    };

    if direction_status != 0 {
        unsafe {
            crate::ffi::pcap_close(handle);
        }

        return Err(
            CaptureError::InterfaceUnavailable
        );
    }

    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_capture_config() {
        let config =
            CaptureConfig::new(1);

        assert!(config.is_some());
        assert!(config.unwrap().validate());
    }

    #[test]
    fn rejects_zero_interface() {
        assert!(
            CaptureConfig::new(0).is_none()
        );
    }

    #[test]
    fn creates_capture_session() {
        let config =
            CaptureConfig::new(1).unwrap();

        let session =
            CaptureSession::new(config);

        assert!(session.is_ok());

        assert_eq!(
            session.unwrap().state(),
            CaptureState::Stopped
        );
    }

    #[test]
    fn starts_capture() {
        let config =
            CaptureConfig::new(1).unwrap();

        let mut session =
            CaptureSession::new(config)
                .unwrap();

        session.start("test-device").unwrap();

        assert!(session.is_running());
    }

    #[test]
    fn cannot_start_twice() {
        let config =
            CaptureConfig::new(1).unwrap();

        let mut session =
            CaptureSession::new(config)
                .unwrap();

        session.start("test-device").unwrap();

        assert_eq!(
            session.start("test-device"),
            Err(CaptureError::AlreadyRunning)
        );
    }

    #[test]
    fn stops_capture() {
        let config =
            CaptureConfig::new(1).unwrap();

        let mut session =
            CaptureSession::new(config)
                .unwrap();

        session.start("test-device").unwrap();
        session.stop().unwrap();

        assert_eq!(
            session.state(),
            CaptureState::Stopped
        );
    }

    #[test]
    fn cannot_stop_when_stopped() {
        let config =
            CaptureConfig::new(1).unwrap();

        let mut session =
            CaptureSession::new(config)
                .unwrap();

        assert_eq!(
            session.stop(),
            Err(CaptureError::NotRunning)
        );
    }

    #[test]
    fn creates_captured_packet() {
        let packet =
            CapturedPacket::new(
                vec![1, 2, 3, 4],
                1,
            );

        assert!(packet.is_some());

        let packet = packet.unwrap();

        assert_eq!(packet.len(), 4);

        assert_eq!(
            packet.original_length,
            4
        );
    }

    #[test]
    fn creates_captured_packet_with_original_length() {
        let packet =
            CapturedPacket::with_original_length(
                vec![1, 2, 3, 4],
                1,
                8,
            );

        assert!(packet.is_some());

        let packet = packet.unwrap();

        assert_eq!(packet.len(), 4);

        assert_eq!(
            packet.original_length,
            8
        );
    }

    #[test]
    fn rejects_invalid_original_length() {
        let packet =
            CapturedPacket::with_original_length(
                vec![1, 2, 3, 4],
                1,
                3,
            );

        assert!(packet.is_none());
    }

    #[test]
    fn rejects_empty_packet() {
        let packet =
            CapturedPacket::new(
                Vec::new(),
                1,
            );

        assert!(packet.is_none());
    }

    #[test]
    fn records_packet_statistics() {
        let config =
            CaptureConfig::new(1).unwrap();

        let mut session =
            CaptureSession::new(config)
                .unwrap();

        session.start("test-device").unwrap();

        let packet =
            CapturedPacket::new(
                vec![0u8; 100],
                1,
            )
            .unwrap();

        session
            .record_packet(&packet)
            .unwrap();

        assert_eq!(
            session.packets_received(),
            1
        );

        assert_eq!(
            session.bytes_received(),
            100
        );
    }

    #[test]
    fn rejects_packet_from_other_interface() {
        let config =
            CaptureConfig::new(1).unwrap();

        let mut session =
            CaptureSession::new(config)
                .unwrap();

        session.start("test-device").unwrap();

        let packet =
            CapturedPacket::new(
                vec![1, 2, 3],
                2,
            )
            .unwrap();

        assert_eq!(
            session.record_packet(&packet),
            Err(CaptureError::InvalidPacket)
        );
    }

    #[test]
    fn rejects_packet_larger_than_original_length() {
        let config =
            CaptureConfig::new(1).unwrap();

        let mut session =
            CaptureSession::new(config)
                .unwrap();

        session.start("test-device").unwrap();

        let packet =
            CapturedPacket {
                data: vec![0u8; 100],
                timestamp: SystemTime::now(),
                interface_index: 1,
                original_length: 50,
            };

        assert_eq!(
            session.record_packet(&packet),
            Err(CaptureError::InvalidPacket)
        );
    }

    #[test]
    fn rejects_packet_larger_than_snaplen() {
        let mut config =
            CaptureConfig::new(1).unwrap();

        config.snaplen = 64;

        let mut session =
            CaptureSession::new(config)
                .unwrap();

        session.start("test-device").unwrap();

        let packet =
            CapturedPacket::new(
                vec![0u8; 65],
                1,
            )
            .unwrap();

        assert_eq!(
            session.record_packet(&packet),
            Err(CaptureError::InvalidPacket)
        );
    }

    #[test]
    fn statistics_can_be_reset() {
        let config =
            CaptureConfig::new(1).unwrap();

        let mut session =
            CaptureSession::new(config)
                .unwrap();

        session.start("test-device").unwrap();

        let packet =
            CapturedPacket::new(
                vec![0u8; 32],
                1,
            )
            .unwrap();

        session
            .record_packet(&packet)
            .unwrap();

        session.reset_statistics();

        assert_eq!(
            session.packets_received(),
            0
        );

        assert_eq!(
            session.bytes_received(),
            0
        );
    }

    #[test]
    fn preserves_native_timestamp() {
        let timestamp =
            SystemTime::UNIX_EPOCH
                + std::time::Duration::from_secs(123);

        let packet =
            CapturedPacket::from_pcap(
                vec![1, 2, 3],
                1,
                3,
                timestamp,
            )
            .unwrap();

        assert_eq!(
            packet.timestamp,
            timestamp
        );
    }
}