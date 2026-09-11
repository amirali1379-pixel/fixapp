#![forbid(unsafe_code)]

use network_core::EngineError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WfpIpVersion {
    Unknown = 0,
    V4 = 4,
    V6 = 6,
}

impl TryFrom<u8> for WfpIpVersion {
    type Error = EngineError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Unknown),
            4 => Ok(Self::V4),
            6 => Ok(Self::V6),
            _ => Err(EngineError::invalid_argument()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WfpDirection {
    Unknown = 0,
    Inbound = 1,
    Outbound = 2,
}

impl TryFrom<u8> for WfpDirection {
    type Error = EngineError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Unknown),
            1 => Ok(Self::Inbound),
            2 => Ok(Self::Outbound),
            _ => Err(EngineError::invalid_argument()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfpMetadata {
    pub layer_id: u16,
    pub callout_id: u64,
    pub filter_id: Option<u64>,
    pub flow_id: Option<u64>,
    pub process_id: Option<u32>,
    pub thread_id: Option<u32>,
    pub application_id: Vec<u8>,
    pub ip_version: WfpIpVersion,
    pub direction: WfpDirection,
    pub interface_index: Option<u32>,
    pub sub_interface_index: Option<u32>,
    pub compartment_id: Option<u32>,
    pub transport_protocol: Option<u8>,
    pub local_address: Option<Vec<u8>>,
    pub remote_address: Option<Vec<u8>>,
    pub local_port: Option<u16>,
    pub remote_port: Option<u16>,
}

impl WfpMetadata {
    pub fn new(
        layer_id: u16,
        callout_id: u64,
    ) -> Self {
        Self {
            layer_id,
            callout_id,
            filter_id: None,
            flow_id: None,
            process_id: None,
            thread_id: None,
            application_id: Vec::new(),
            ip_version: WfpIpVersion::Unknown,
            direction: WfpDirection::Unknown,
            interface_index: None,
            sub_interface_index: None,
            compartment_id: None,
            transport_protocol: None,
            local_address: None,
            remote_address: None,
            local_port: None,
            remote_port: None,
        }
    }

    pub fn set_filter_id(
        &mut self,
        filter_id: Option<u64>,
    ) {
        self.filter_id = filter_id;
    }

    pub fn set_flow_id(
        &mut self,
        flow_id: Option<u64>,
    ) {
        self.flow_id = flow_id;
    }

    pub fn set_process(
        &mut self,
        process_id: Option<u32>,
        thread_id: Option<u32>,
    ) {
        self.process_id = process_id;
        self.thread_id = thread_id;
    }

    pub fn set_application_id(
        &mut self,
        application_id: Vec<u8>,
    ) {
        self.application_id = application_id;
    }

    pub fn set_ip_version(
        &mut self,
        version: WfpIpVersion,
    ) {
        self.ip_version = version;
    }

    pub fn set_direction(
        &mut self,
        direction: WfpDirection,
    ) {
        self.direction = direction;
    }

    pub fn set_interface(
        &mut self,
        interface_index: Option<u32>,
        sub_interface_index: Option<u32>,
    ) {
        self.interface_index = interface_index;
        self.sub_interface_index =
            sub_interface_index;
    }

    pub fn set_compartment(
        &mut self,
        compartment_id: Option<u32>,
    ) {
        self.compartment_id = compartment_id;
    }

    pub fn set_transport(
        &mut self,
        protocol: Option<u8>,
        local_port: Option<u16>,
        remote_port: Option<u16>,
    ) {
        self.transport_protocol = protocol;
        self.local_port = local_port;
        self.remote_port = remote_port;
    }

    pub fn set_addresses(
        &mut self,
        local: Vec<u8>,
        remote: Vec<u8>,
    ) -> Result<(), EngineError> {
        if local.len() != 4
            && local.len() != 16
        {
            return Err(
                EngineError::invalid_argument()
            );
        }

        if remote.len() != 4
            && remote.len() != 16
        {
            return Err(
                EngineError::invalid_argument()
            );
        }

        if local.len() != remote.len() {
            return Err(
                EngineError::invalid_argument()
            );
        }

        self.local_address = Some(local);
        self.remote_address = Some(remote);

        self.ip_version =
            match self.local_address
                .as_ref()
                .map(Vec::len)
            {
                Some(4) => WfpIpVersion::V4,
                Some(16) => WfpIpVersion::V6,
                _ => WfpIpVersion::Unknown,
            };

        Ok(())
    }

    pub fn has_flow_context(&self) -> bool {
        self.flow_id.is_some()
    }

    pub fn has_process_context(&self) -> bool {
        self.process_id.is_some()
    }

    pub fn has_interface_context(&self) -> bool {
        self.interface_index.is_some()
    }

    pub fn has_transport_context(&self) -> bool {
        self.transport_protocol.is_some()
    }

    pub fn is_ipv4(&self) -> bool {
        self.ip_version == WfpIpVersion::V4
    }

    pub fn is_ipv6(&self) -> bool {
        self.ip_version == WfpIpVersion::V6
    }

    pub fn is_inbound(&self) -> bool {
        self.direction == WfpDirection::Inbound
    }

    pub fn is_outbound(&self) -> bool {
        self.direction == WfpDirection::Outbound
    }

    pub fn is_tcp(&self) -> bool {
        self.transport_protocol == Some(6)
    }

    pub fn is_udp(&self) -> bool {
        self.transport_protocol == Some(17)
    }

    pub fn is_icmp(&self) -> bool {
        self.transport_protocol == Some(1)
            && self.is_ipv4()
    }

    pub fn is_icmpv6(&self) -> bool {
        self.transport_protocol == Some(58)
            && self.is_ipv6()
    }

    pub fn clear_runtime_context(&mut self) {
        self.flow_id = None;
        self.filter_id = None;
        self.process_id = None;
        self.thread_id = None;
    }
}

impl Default for WfpMetadata {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_empty_metadata() {
        let metadata =
            WfpMetadata::new(10, 20);

        assert_eq!(
            metadata.layer_id,
            10
        );

        assert_eq!(
            metadata.callout_id,
            20
        );

        assert_eq!(
            metadata.ip_version,
            WfpIpVersion::Unknown
        );
    }

    #[test]
    fn sets_flow_and_process_context() {
        let mut metadata =
            WfpMetadata::default();

        metadata.set_flow_id(Some(100));
        metadata.set_process(
            Some(200),
            Some(300),
        );

        assert!(
            metadata.has_flow_context()
        );

        assert!(
            metadata.has_process_context()
        );

        assert_eq!(
            metadata.flow_id,
            Some(100)
        );

        assert_eq!(
            metadata.process_id,
            Some(200)
        );

        assert_eq!(
            metadata.thread_id,
            Some(300)
        );
    }

    #[test]
    fn sets_ipv4_addresses() {
        let mut metadata =
            WfpMetadata::default();

        metadata
            .set_addresses(
                vec![192, 168, 1, 10],
                vec![8, 8, 8, 8],
            )
            .unwrap();

        assert!(
            metadata.is_ipv4()
        );

        assert!(
            !metadata.is_ipv6()
        );

        assert_eq!(
            metadata.local_address,
            Some(vec![192, 168, 1, 10])
        );
    }

    #[test]
    fn sets_ipv6_addresses() {
        let mut metadata =
            WfpMetadata::default();

        metadata
            .set_addresses(
                vec![0; 16],
                vec![1; 16],
            )
            .unwrap();

        assert!(
            metadata.is_ipv6()
        );
    }

    #[test]
    fn rejects_invalid_address_length() {
        let mut metadata =
            WfpMetadata::default();

        assert!(
            metadata
                .set_addresses(
                    vec![1, 2, 3],
                    vec![4, 5, 6],
                )
                .is_err()
        );
    }

    #[test]
    fn rejects_mixed_address_families() {
        let mut metadata =
            WfpMetadata::default();

        assert!(
            metadata
                .set_addresses(
                    vec![192, 168, 1, 1],
                    vec![0; 16],
                )
                .is_err()
        );
    }

    #[test]
    fn transport_helpers_work() {
        let mut metadata =
            WfpMetadata::default();

        metadata.set_ip_version(
            WfpIpVersion::V4
        );

        metadata.set_transport(
            Some(6),
            Some(1234),
            Some(443),
        );

        assert!(
            metadata.has_transport_context()
        );

        assert!(metadata.is_tcp());
        assert!(!metadata.is_udp());
        assert!(metadata.is_icmp() == false);

        assert_eq!(
            metadata.local_port,
            Some(1234)
        );

        assert_eq!(
            metadata.remote_port,
            Some(443)
        );
    }

    #[test]
    fn direction_helpers_work() {
        let mut metadata =
            WfpMetadata::default();

        metadata.set_direction(
            WfpDirection::Inbound
        );

        assert!(
            metadata.is_inbound()
        );

        assert!(
            !metadata.is_outbound()
        );

        metadata.set_direction(
            WfpDirection::Outbound
        );

        assert!(
            metadata.is_outbound()
        );
    }

    #[test]
    fn clears_runtime_context() {
        let mut metadata =
            WfpMetadata::default();

        metadata.set_flow_id(Some(1));
        metadata.set_filter_id(Some(2));
        metadata.set_process(
            Some(3),
            Some(4),
        );

        metadata.clear_runtime_context();

        assert_eq!(
            metadata.flow_id,
            None
        );

        assert_eq!(
            metadata.filter_id,
            None
        );

        assert_eq!(
            metadata.process_id,
            None
        );

        assert_eq!(
            metadata.thread_id,
            None
        );
    }
}