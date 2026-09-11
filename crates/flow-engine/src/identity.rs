#![forbid(unsafe_code)]

use network_core::{FlowKey as CoreFlowKey, Protocol};
use crate::key::FlowKey;

/// Canonical Flow Engine identity boundary.
///
/// `network_core::FlowKey` is authoritative. The local flow-engine key is a
/// packet-facing compatibility type and is converted here before identity is
/// created or compared.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowIdentity { key: CoreFlowKey }

impl FlowIdentity {
    pub fn from_key(key: CoreFlowKey) -> Self { Self { key } }

    pub fn from_flow_key(key: &FlowKey) -> Self {
        Self::from_key(CoreFlowKey::normalized(
            key.source_ip,
            key.source_port,
            key.destination_ip,
            key.destination_port,
            protocol_from_u8(key.protocol),
        ))
    }

    pub fn key(&self) -> &CoreFlowKey { &self.key }
    pub fn into_key(self) -> CoreFlowKey { self.key }
}

fn protocol_from_u8(protocol: u8) -> Protocol {
    match protocol {
        6 => Protocol::Tcp,
        17 => Protocol::Udp,
        1 => Protocol::Icmp,
        58 => Protocol::IcmpV6,
        value => Protocol::Other(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> FlowKey {
        FlowKey::new("10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap(), 1234, 443, 6)
    }

    #[test]
    fn creates_canonical_identity() {
        let identity = FlowIdentity::from_flow_key(&key());
        assert_eq!(identity.key().src_port, 1234);
        assert_eq!(identity.key().dst_port, 443);
        assert_eq!(identity.key().protocol, Protocol::Tcp);
    }

    #[test]
    fn reverse_observation_maps_to_same_identity() {
        let first = FlowIdentity::from_flow_key(&key());
        let second = FlowIdentity::from_flow_key(&key().reverse());
        assert_eq!(first, second);
    }
}
