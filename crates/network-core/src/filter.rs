use crate::{Direction, Protocol};
use std::net::IpAddr;
use std::ops::RangeInclusive;

/// Address matching rule used by backend-independent filters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressMatch {
    Exact(IpAddr),
    Network { address: IpAddr, prefix_len: u8 },
}

impl AddressMatch {
    pub fn exact(address: IpAddr) -> Self {
        Self::Exact(address)
    }

    pub fn network(address: IpAddr, prefix_len: u8) -> Option<Self> {
        let max = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        (prefix_len <= max).then_some(Self::Network { address, prefix_len })
    }

    pub fn matches(&self, candidate: IpAddr) -> bool {
        match self {
            Self::Exact(address) => *address == candidate,
            Self::Network { address, prefix_len } => {
                match (address, candidate) {
                    (IpAddr::V4(network), IpAddr::V4(value)) => {
                        let prefix = *prefix_len as u32;
                        let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
                        (u32::from_be_bytes(network.octets()) & mask)
                            == (u32::from_be_bytes(value.octets()) & mask)
                    }
                    (IpAddr::V6(network), IpAddr::V6(value)) => {
                        let prefix = *prefix_len as usize;
                        let network = u128::from_be_bytes(network.octets());
                        let value = u128::from_be_bytes(value.octets());
                        let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
                        (network & mask) == (value & mask)
                    }
                    _ => false,
                }
            }
        }
    }
}

/// Port matching rule. A single port is represented by an inclusive range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortMatch(pub RangeInclusive<u16>);

impl PortMatch {
    pub fn exact(port: u16) -> Self {
        Self(port..=port)
    }

    pub fn range(start: u16, end: u16) -> Option<Self> {
        (start <= end).then_some(Self(start..=end))
    }

    pub fn matches(&self, port: u16) -> bool {
        self.0.contains(&port)
    }
}

/// Backend-independent packet filter.
///
/// Every field is optional, so a filter can constrain only the dimensions
/// relevant to a backend. Backends are responsible for translating this
/// contract into their native filter language/API.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Filter {
    pub expression: String,
    pub source_address: Option<AddressMatch>,
    pub destination_address: Option<AddressMatch>,
    pub source_port: Option<PortMatch>,
    pub destination_port: Option<PortMatch>,
    pub protocol: Option<Protocol>,
    pub direction: Option<Direction>,
}

impl Filter {
    /// Preserves the original expression-based constructor for compatibility.
    pub fn new(expression: &str) -> Self {
        Self {
            expression: expression.to_string(),
            ..Self::default()
        }
    }

    pub fn matches(
        &self,
        source_address: Option<IpAddr>,
        destination_address: Option<IpAddr>,
        source_port: Option<u16>,
        destination_port: Option<u16>,
        protocol: Option<Protocol>,
        direction: Option<Direction>,
    ) -> bool {
        self.source_address
            .as_ref()
            .map_or(true, |rule| source_address.map_or(false, |value| rule.matches(value)))
            && self
                .destination_address
                .as_ref()
                .map_or(true, |rule| destination_address.map_or(false, |value| rule.matches(value)))
            && self
                .source_port
                .as_ref()
                .map_or(true, |rule| source_port.map_or(false, |value| rule.matches(value)))
            && self
                .destination_port
                .as_ref()
                .map_or(true, |rule| destination_port.map_or(false, |value| rule.matches(value)))
            && self.protocol.map_or(true, |rule| protocol == Some(rule))
            && self.direction.map_or(true, |rule| direction == Some(rule))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn ipv4_network_match() {
        let rule = AddressMatch::network(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24).unwrap();
        assert!(rule.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42))));
        assert!(!rule.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 42))));
    }

    #[test]
    fn ipv6_network_match() {
        let rule = AddressMatch::network(IpAddr::V6(Ipv6Addr::LOCALHOST), 128).unwrap();
        assert!(rule.matches(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!rule.matches(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    }

    #[test]
    fn port_range_is_bounded() {
        let rule = PortMatch::range(1000, 2000).unwrap();
        assert!(rule.matches(1000));
        assert!(rule.matches(1500));
        assert!(rule.matches(2000));
        assert!(!rule.matches(2001));
    }

    #[test]
    fn filter_matches_only_configured_dimensions() {
        let mut filter = Filter::default();
        filter.protocol = Some(Protocol::Udp);
        filter.direction = Some(Direction::Outbound);

        assert!(filter.matches(
            None,
            None,
            None,
            None,
            Some(Protocol::Udp),
            Some(Direction::Outbound),
        ));
        assert!(!filter.matches(
            None,
            None,
            None,
            None,
            Some(Protocol::Tcp),
            Some(Direction::Outbound),
        ));
    }
}
