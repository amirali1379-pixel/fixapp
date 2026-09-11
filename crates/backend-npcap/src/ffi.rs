use std::ffi::{c_char, c_int, c_uchar, c_uint, c_void};

pub type PcapT = c_void;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PcapPkthdr {
    pub ts_sec: i64,
    pub ts_usec: i64,
    pub caplen: c_uint,
    pub len: c_uint,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PcapAddr {
    pub next: *mut PcapAddr,
    pub addr: *mut c_void,
    pub netmask: *mut c_void,
    pub broadaddr: *mut c_void,
    pub dstaddr: *mut c_void,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PcapIf {
    pub next: *mut PcapIf,
    pub name: *mut c_char,
    pub description: *mut c_char,
    pub addresses: *mut PcapAddr,
    pub flags: c_uint,
}

pub const PCAP_ERRBUF_SIZE: usize = 256;

pub const PCAP_IF_LOOPBACK: c_uint = 0x0000_0001;
pub const PCAP_IF_UP: c_uint = 0x0000_0002;
pub const PCAP_IF_RUNNING: c_uint = 0x0000_0004;
pub const PCAP_IF_WIRELESS: c_uint = 0x0000_0008;

pub const PCAP_D_INOUT: c_int = 0;
pub const PCAP_D_IN: c_int = 1;
pub const PCAP_D_OUT: c_int = 2;

pub const PCAP_NETMASK_UNKNOWN: c_uint = 0xffff_ffff;

/// pcap_next_ex return values.
pub const PCAP_NEXT_EX_ERROR: c_int = -1;
pub const PCAP_NEXT_EX_PACKET: c_int = 1;
pub const PCAP_NEXT_EX_TIMEOUT: c_int = 0;
pub const PCAP_NEXT_EX_EOF: c_int = -2;

#[cfg(windows)]
#[link(name = "wpcap")]
unsafe extern "C" {
    pub fn pcap_findalldevs(
        alldevs: *mut *mut PcapIf,
        errbuf: *mut c_char,
    ) -> c_int;

    pub fn pcap_freealldevs(
        alldevs: *mut PcapIf,
    );

    pub fn pcap_open_live(
        device: *const c_char,
        snaplen: c_int,
        promisc: c_int,
        to_ms: c_int,
        errbuf: *mut c_char,
    ) -> *mut PcapT;

    pub fn pcap_close(
        handle: *mut PcapT,
    );

    pub fn pcap_next_ex(
        handle: *mut PcapT,
        pkt_header: *mut *mut PcapPkthdr,
        pkt_data: *mut *mut c_uchar,
    ) -> c_int;

    pub fn pcap_sendpacket(
        handle: *mut PcapT,
        buffer: *const c_uchar,
        size: c_int,
    ) -> c_int;

    pub fn pcap_setdirection(
        handle: *mut PcapT,
        direction: c_int,
    ) -> c_int;

    pub fn pcap_geterr(
        handle: *mut PcapT,
    ) -> *const c_char;
}

#[cfg(not(windows))]
pub unsafe fn pcap_findalldevs(
    _alldevs: *mut *mut PcapIf,
    _errbuf: *mut c_char,
) -> c_int {
    -1
}

#[cfg(not(windows))]
pub unsafe fn pcap_freealldevs(
    _alldevs: *mut PcapIf,
) {
}

#[cfg(not(windows))]
pub unsafe fn pcap_open_live(
    _device: *const c_char,
    _snaplen: c_int,
    _promisc: c_int,
    _to_ms: c_int,
    _errbuf: *mut c_char,
) -> *mut PcapT {
    std::ptr::null_mut()
}

#[cfg(not(windows))]
pub unsafe fn pcap_close(
    _handle: *mut PcapT,
) {
}

#[cfg(not(windows))]
pub unsafe fn pcap_next_ex(
    _handle: *mut PcapT,
    _pkt_header: *mut *mut PcapPkthdr,
    _pkt_data: *mut *mut c_uchar,
) -> c_int {
    PCAP_NEXT_EX_ERROR
}

#[cfg(not(windows))]
pub unsafe fn pcap_sendpacket(
    _handle: *mut PcapT,
    _buffer: *const c_uchar,
    _size: c_int,
) -> c_int {
    -1
}

#[cfg(not(windows))]
pub unsafe fn pcap_setdirection(
    _handle: *mut PcapT,
    _direction: c_int,
) -> c_int {
    -1
}

#[cfg(not(windows))]
pub unsafe fn pcap_geterr(
    _handle: *mut PcapT,
) -> *const c_char {
    std::ptr::null()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcapDirection {
    InOut,
    In,
    Out,
}

impl PcapDirection {
    pub fn as_raw(self) -> c_int {
        match self {
            Self::InOut => PCAP_D_INOUT,
            Self::In => PCAP_D_IN,
            Self::Out => PCAP_D_OUT,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcapOpenError {
    InvalidDevice,
    OpenFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcapSendError {
    InvalidHandle,
    PacketTooLarge,
    SendFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcapReceiveStatus {
    Packet,
    Timeout,
    EndOfCapture,
    Error,
}

impl PcapReceiveStatus {
    pub fn from_raw(value: c_int) -> Self {
        match value {
            PCAP_NEXT_EX_PACKET => Self::Packet,
            PCAP_NEXT_EX_TIMEOUT => Self::Timeout,
            PCAP_NEXT_EX_EOF => Self::EndOfCapture,
            _ => Self::Error,
        }
    }

    pub fn is_packet(self) -> bool {
        matches!(self, Self::Packet)
    }

    pub fn is_timeout(self) -> bool {
        matches!(self, Self::Timeout)
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::EndOfCapture | Self::Error
        )
    }
}

pub fn validate_packet_length(
    length: usize,
) -> Result<c_int, PcapSendError> {
    if length == 0 {
        return Err(
            PcapSendError::SendFailed
        );
    }

    if length > c_int::MAX as usize {
        return Err(
            PcapSendError::PacketTooLarge
        );
    }

    Ok(length as c_int)
}

/// Converts a native pcap timestamp into `SystemTime`.
///
/// Npcap timestamps are wall-clock timestamps while the engine's
/// authoritative `Timestamp` is monotonic. The capture layer should
/// preserve this native timestamp separately rather than pretending
/// it is directly convertible to the engine's monotonic clock.
pub fn pcap_timestamp_to_system_time(
    header: &PcapPkthdr,
) -> Option<std::time::SystemTime> {
    if header.ts_sec < 0 || header.ts_usec < 0 {
        return None;
    }

    let secs = u64::try_from(header.ts_sec).ok()?;
    let micros = u32::try_from(header.ts_usec).ok()?;

    std::time::UNIX_EPOCH
        .checked_add(std::time::Duration::from_secs(secs))?
        .checked_add(std::time::Duration::from_micros(
            micros as u64,
        ))
}

/// Validates the packet header returned by Npcap.
///
/// `caplen` is the number of bytes actually available in the capture
/// buffer. `len` is the original on-wire packet length and may be
/// larger than `caplen` when a snaplen was applied.
pub fn validate_packet_header(
    header: &PcapPkthdr,
) -> Result<(usize, usize), PcapReceiveStatus> {
    let captured_length =
        usize::try_from(header.caplen)
            .map_err(|_| PcapReceiveStatus::Error)?;

    let original_length =
        usize::try_from(header.len)
            .map_err(|_| PcapReceiveStatus::Error)?;

    if captured_length == 0 {
        return Err(PcapReceiveStatus::Error);
    }

    if original_length == 0 {
        return Err(PcapReceiveStatus::Error);
    }

    if captured_length > original_length {
        return Err(PcapReceiveStatus::Error);
    }

    Ok((
        captured_length,
        original_length,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direction_values_are_correct() {
        assert_eq!(
            PcapDirection::InOut.as_raw(),
            PCAP_D_INOUT
        );

        assert_eq!(
            PcapDirection::In.as_raw(),
            PCAP_D_IN
        );

        assert_eq!(
            PcapDirection::Out.as_raw(),
            PCAP_D_OUT
        );
    }

    #[test]
    fn validates_packet_length() {
        assert_eq!(
            validate_packet_length(100).unwrap(),
            100
        );
    }

    #[test]
    fn rejects_empty_packet() {
        assert_eq!(
            validate_packet_length(0),
            Err(PcapSendError::SendFailed)
        );
    }

    #[test]
    fn rejects_packet_larger_than_c_int() {
        let result =
            validate_packet_length(
                c_int::MAX as usize + 1
            );

        assert_eq!(
            result,
            Err(PcapSendError::PacketTooLarge)
        );
    }

    #[test]
    fn packet_header_has_expected_layout() {
        assert_eq!(
            std::mem::size_of::<PcapPkthdr>(),
            32
        );
    }

    #[test]
    fn interface_flags_are_defined() {
        assert_ne!(
            PCAP_IF_UP,
            0
        );

        assert_ne!(
            PCAP_IF_RUNNING,
            0
        );

        assert_ne!(
            PCAP_IF_LOOPBACK,
            0
        );
    }

    #[test]
    fn receive_status_values_are_correct() {
        assert_eq!(
            PcapReceiveStatus::from_raw(
                PCAP_NEXT_EX_PACKET
            ),
            PcapReceiveStatus::Packet
        );

        assert_eq!(
            PcapReceiveStatus::from_raw(
                PCAP_NEXT_EX_TIMEOUT
            ),
            PcapReceiveStatus::Timeout
        );

        assert_eq!(
            PcapReceiveStatus::from_raw(
                PCAP_NEXT_EX_EOF
            ),
            PcapReceiveStatus::EndOfCapture
        );

        assert_eq!(
            PcapReceiveStatus::from_raw(
                PCAP_NEXT_EX_ERROR
            ),
            PcapReceiveStatus::Error
        );
    }

    #[test]
    fn validates_valid_packet_header() {
        let header = PcapPkthdr {
            ts_sec: 1_000,
            ts_usec: 500,
            caplen: 128,
            len: 256,
        };

        assert_eq!(
            validate_packet_header(&header),
            Ok((128, 256))
        );
    }

    #[test]
    fn rejects_zero_capture_length() {
        let header = PcapPkthdr {
            ts_sec: 1_000,
            ts_usec: 500,
            caplen: 0,
            len: 256,
        };

        assert_eq!(
            validate_packet_header(&header),
            Err(PcapReceiveStatus::Error)
        );
    }

    #[test]
    fn rejects_capture_length_larger_than_original_length() {
        let header = PcapPkthdr {
            ts_sec: 1_000,
            ts_usec: 500,
            caplen: 512,
            len: 256,
        };

        assert_eq!(
            validate_packet_header(&header),
            Err(PcapReceiveStatus::Error)
        );
    }

    #[test]
    fn converts_valid_pcap_timestamp() {
        let header = PcapPkthdr {
            ts_sec: 1,
            ts_usec: 500_000,
            caplen: 64,
            len: 64,
        };

        let timestamp =
            pcap_timestamp_to_system_time(&header)
                .expect("timestamp should be valid");

        assert_eq!(
            timestamp
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap(),
            std::time::Duration::from_micros(1_500_000)
        );
    }

    #[test]
    fn rejects_invalid_pcap_timestamp() {
        let header = PcapPkthdr {
            ts_sec: -1,
            ts_usec: 0,
            caplen: 64,
            len: 64,
        };

        assert!(
            pcap_timestamp_to_system_time(&header)
                .is_none()
        );
    }
}