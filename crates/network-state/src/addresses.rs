#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv6Addr};

/// fe80::/10 — IPv6 unicast link-local range.
///
/// `Ipv6Addr::is_unicast_link_local` is still gated behind the
/// unstable `ip` feature, so this is implemented manually against
/// the well-known prefix.
fn is_unicast_link_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// fc00::/7 — IPv6 unique local address range.
///
/// `Ipv6Addr::is_unique_local` is still gated behind the unstable
/// `ip` feature, so this is implemented manually against the
/// well-known prefix.
fn is_unique_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AddressScope {
    Unknown = 0,
    Host = 1,
    Link = 2,
    Site = 3,
    Global = 4,
}

impl AddressScope {
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => {
                if ip.is_loopback() {
                    Self::Host
                } else if ip.is_link_local() {
                    Self::Link
                } else if ip.is_private() {
                    Self::Site
                } else {
                    Self::Global
                }
            }
            IpAddr::V6(ip) => {
                if ip.is_loopback() {
                    Self::Host
                } else if is_unicast_link_local(ip) {
                    Self::Link
                } else if is_unique_local(ip) {
                    Self::Site
                } else {
                    Self::Global
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AddressState {
    Unknown = 0,
    Tentative = 1,
    Preferred = 2,
    Deprecated = 3,
    Invalid = 4,
}

impl AddressState {
    pub fn is_usable(self) -> bool {
        matches!(
            self,
            Self::Preferred | Self::Deprecated
        )
    }

    pub fn is_preferred(self) -> bool {
        self == Self::Preferred
    }

    pub fn is_terminal(self) -> bool {
        self == Self::Invalid
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AddressInfo {
    pub interface_id: u64,
    pub address: IpAddr,
    pub prefix_length: u8,
    pub scope: AddressScope,
    pub state: AddressState,
    pub dns_eligible: bool,
    pub default_route_eligible: bool,
}

impl AddressInfo {
    pub fn new(
        interface_id: u64,
        address: IpAddr,
        prefix_length: u8,
    ) -> Option<Self> {
        let max_prefix = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        if prefix_length > max_prefix {
            return None;
        }

        Some(Self {
            interface_id,
            address,
            prefix_length,
            scope: AddressScope::from_ip(address),
            state: AddressState::Preferred,
            dns_eligible: true,
            default_route_eligible: true,
        })
    }

    pub fn network_prefix(&self) -> IpAddr {
        match self.address {
            IpAddr::V4(ip) => {
                let value = u32::from(ip);

                let mask = if self.prefix_length == 0 {
                    0
                } else {
                    u32::MAX
                        << (32 - self.prefix_length)
                };

                IpAddr::V4(
                    std::net::Ipv4Addr::from(
                        value & mask
                    )
                )
            }

            IpAddr::V6(ip) => {
                let value = u128::from(ip);

                let mask = if self.prefix_length == 0 {
                    0
                } else {
                    u128::MAX
                        << (128 - self.prefix_length)
                };

                IpAddr::V6(
                    std::net::Ipv6Addr::from(
                        value & mask
                    )
                )
            }
        }
    }

    pub fn contains(
        &self,
        ip: IpAddr,
    ) -> bool {
        match (self.address, ip) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                let prefix = self.prefix_length;

                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };

                (u32::from(network) & mask)
                    == (u32::from(candidate) & mask)
            }

            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                let prefix = self.prefix_length;

                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };

                (u128::from(network) & mask)
                    == (u128::from(candidate) & mask)
            }

            _ => false,
        }
    }

    pub fn is_ipv4(&self) -> bool {
        self.address.is_ipv4()
    }

    pub fn is_ipv6(&self) -> bool {
        self.address.is_ipv6()
    }

    pub fn is_usable(&self) -> bool {
        self.state.is_usable()
    }

    pub fn with_state(
        mut self,
        state: AddressState,
    ) -> Self {
        self.state = state;
        self
    }

    pub fn with_dns_eligibility(
        mut self,
        eligible: bool,
    ) -> Self {
        self.dns_eligible = eligible;
        self
    }

    pub fn with_default_route_eligibility(
        mut self,
        eligible: bool,
    ) -> Self {
        self.default_route_eligible = eligible;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_ipv4_address() {
        let info = AddressInfo::new(
            1,
            "192.168.1.10".parse().unwrap(),
            24,
        )
        .unwrap();

        assert_eq!(
            info.interface_id,
            1
        );

        assert_eq!(
            info.prefix_length,
            24
        );

        assert_eq!(
            info.scope,
            AddressScope::Site
        );

        assert!(info.is_ipv4());
        assert!(!info.is_ipv6());
        assert!(info.is_usable());
    }

    #[test]
    fn creates_ipv6_address() {
        let info = AddressInfo::new(
            2,
            "2001:db8::10".parse().unwrap(),
            64,
        )
        .unwrap();

        assert!(info.is_ipv6());
        assert!(!info.is_ipv4());

        assert_eq!(
            info.prefix_length,
            64
        );
    }

    #[test]
    fn rejects_invalid_ipv4_prefix() {
        assert!(
            AddressInfo::new(
                1,
                "192.168.1.1".parse().unwrap(),
                33,
            )
            .is_none()
        );
    }

    #[test]
    fn rejects_invalid_ipv6_prefix() {
        assert!(
            AddressInfo::new(
                1,
                "::1".parse().unwrap(),
                129,
            )
            .is_none()
        );
    }

    #[test]
    fn calculates_ipv4_network_prefix() {
        let info = AddressInfo::new(
            1,
            "192.168.1.123".parse().unwrap(),
            24,
        )
        .unwrap();

        assert_eq!(
            info.network_prefix(),
            "192.168.1.0".parse::<std::net::IpAddr>().unwrap()
        );
    }

    #[test]
    fn calculates_ipv6_network_prefix() {
        let info = AddressInfo::new(
            1,
            "2001:db8:1234:5678::10"
                .parse()
                .unwrap(),
            64,
        )
        .unwrap();

        assert_eq!(
            info.network_prefix(),
            "2001:db8:1234:5678::"
                .parse::<std::net::IpAddr>()
                .unwrap()
        );
    }

    #[test]
    fn contains_ipv4_address() {
        let info = AddressInfo::new(
            1,
            "192.168.1.10".parse().unwrap(),
            24,
        )
        .unwrap();

        assert!(
            info.contains(
                "192.168.1.200"
                    .parse()
                    .unwrap()
            )
        );

        assert!(
            !info.contains(
                "192.168.2.1"
                    .parse()
                    .unwrap()
            )
        );
    }

    #[test]
    fn contains_ipv6_address() {
        let info = AddressInfo::new(
            1,
            "2001:db8:1::10"
                .parse()
                .unwrap(),
            64,
        )
        .unwrap();

        assert!(
            info.contains(
                "2001:db8:1::20"
                    .parse()
                    .unwrap()
            )
        );

        assert!(
            !info.contains(
                "2001:db8:2::1"
                    .parse()
                    .unwrap()
            )
        );
    }

    #[test]
    fn different_ip_versions_do_not_match() {
        let info = AddressInfo::new(
            1,
            "192.168.1.1".parse().unwrap(),
            24,
        )
        .unwrap();

        assert!(
            !info.contains(
                "2001:db8::1"
                    .parse()
                    .unwrap()
            )
        );
    }

    #[test]
    fn scope_detection() {
        assert_eq!(
            AddressScope::from_ip(
                "127.0.0.1".parse().unwrap()
            ),
            AddressScope::Host
        );

        assert_eq!(
            AddressScope::from_ip(
                "169.254.1.1".parse().unwrap()
            ),
            AddressScope::Link
        );

        assert_eq!(
            AddressScope::from_ip(
                "192.168.1.1".parse().unwrap()
            ),
            AddressScope::Site
        );

        assert_eq!(
            AddressScope::from_ip(
                "8.8.8.8".parse().unwrap()
            ),
            AddressScope::Global
        );
    }

    #[test]
    fn address_state_helpers() {
        assert!(
            AddressState::Preferred.is_usable()
        );

        assert!(
            AddressState::Deprecated.is_usable()
        );

        assert!(
            !AddressState::Tentative.is_usable()
        );

        assert!(
            AddressState::Invalid.is_terminal()
        );
    }

    #[test]
    fn builder_methods_work() {
        let info = AddressInfo::new(
            1,
            "10.0.0.1".parse().unwrap(),
            8,
        )
        .unwrap()
        .with_state(AddressState::Deprecated)
        .with_dns_eligibility(false)
        .with_default_route_eligibility(false);

        assert_eq!(
            info.state,
            AddressState::Deprecated
        );

        assert!(!info.dns_eligible);
        assert!(!info.default_route_eligible);
    }
}