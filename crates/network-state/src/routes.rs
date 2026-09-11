#![forbid(unsafe_code)]

use std::fmt;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RouteProtocol {
    Unknown = 0,
    Other = 1,
    Local = 2,
    Static = 3,
    Dhcp = 4,
    RouterAdvertisement = 5,
    NetMgmt = 6,
}

impl fmt::Display for RouteProtocol {
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        let value = match self {
            Self::Unknown => "unknown",
            Self::Other => "other",
            Self::Local => "local",
            Self::Static => "static",
            Self::Dhcp => "dhcp",
            Self::RouterAdvertisement => "router-advertisement",
            Self::NetMgmt => "netmgmt",
        };

        f.write_str(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RouteType {
    Unknown = 0,
    Other = 1,
    Unicast = 2,
    Local = 3,
    Broadcast = 4,
    Multicast = 5,
    Blackhole = 6,
    Unreachable = 7,
    Prohibit = 8,
}

impl RouteType {
    pub fn is_forwarding(&self) -> bool {
        matches!(
            self,
            Self::Unicast
        )
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Blackhole
                | Self::Unreachable
                | Self::Prohibit
        )
    }
}

impl fmt::Display for RouteType {
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        let value = match self {
            Self::Unknown => "unknown",
            Self::Other => "other",
            Self::Unicast => "unicast",
            Self::Local => "local",
            Self::Broadcast => "broadcast",
            Self::Multicast => "multicast",
            Self::Blackhole => "blackhole",
            Self::Unreachable => "unreachable",
            Self::Prohibit => "prohibit",
        };

        f.write_str(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RouteInfo {
    pub id: u64,
    pub destination: IpAddr,
    pub prefix_length: u8,
    pub gateway: Option<IpAddr>,
    pub interface_id: u64,
    pub metric: u32,
    pub protocol: RouteProtocol,
    pub route_type: RouteType,
    pub enabled: bool,
}

impl RouteInfo {
    pub fn new(
        id: u64,
        destination: IpAddr,
        prefix_length: u8,
        interface_id: u64,
    ) -> Option<Self> {
        let max_prefix = match destination {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        if prefix_length > max_prefix {
            return None;
        }

        Some(Self {
            id,
            destination,
            prefix_length,
            gateway: None,
            interface_id,
            metric: 0,
            protocol: RouteProtocol::Unknown,
            route_type: RouteType::Unicast,
            enabled: true,
        })
    }

    pub fn with_gateway(
        mut self,
        gateway: IpAddr,
    ) -> Option<Self> {
        if gateway.is_ipv4() != self.destination.is_ipv4() {
            return None;
        }

        self.gateway = Some(gateway);
        Some(self)
    }

    pub fn with_metric(
        mut self,
        metric: u32,
    ) -> Self {
        self.metric = metric;
        self
    }

    pub fn with_protocol(
        mut self,
        protocol: RouteProtocol,
    ) -> Self {
        self.protocol = protocol;
        self
    }

    pub fn with_route_type(
        mut self,
        route_type: RouteType,
    ) -> Self {
        self.route_type = route_type;
        self
    }

    pub fn with_enabled(
        mut self,
        enabled: bool,
    ) -> Self {
        self.enabled = enabled;
        self
    }

    pub fn is_ipv4(&self) -> bool {
        self.destination.is_ipv4()
    }

    pub fn is_ipv6(&self) -> bool {
        self.destination.is_ipv6()
    }

    pub fn is_default(&self) -> bool {
        self.prefix_length == 0
    }

    pub fn is_usable(&self) -> bool {
        self.enabled
            && self.route_type.is_forwarding()
    }

    pub fn network_prefix(&self) -> IpAddr {
        match self.destination {
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
        if self.destination.is_ipv4()
            != ip.is_ipv4()
        {
            return false;
        }

        match (self.destination, ip) {
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
}

impl fmt::Display for RouteInfo {
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        write!(
            f,
            "{}/{} -> {:?}, if={}, metric={}, {}",
            self.destination,
            self.prefix_length,
            self.gateway,
            self.interface_id,
            self.metric,
            self.route_type
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_ipv4_route() {
        let route = RouteInfo::new(
            1,
            "192.168.1.0".parse().unwrap(),
            24,
            10,
        )
        .unwrap();

        assert_eq!(route.id, 1);
        assert_eq!(route.interface_id, 10);
        assert_eq!(route.prefix_length, 24);
        assert!(route.is_ipv4());
        assert!(!route.is_ipv6());
        assert!(!route.is_default());
        assert!(route.is_usable());
    }

    #[test]
    fn creates_ipv6_route() {
        let route = RouteInfo::new(
            2,
            "2001:db8:1::".parse().unwrap(),
            64,
            20,
        )
        .unwrap();

        assert!(route.is_ipv6());
        assert!(!route.is_ipv4());
    }

    #[test]
    fn rejects_invalid_prefix() {
        assert!(
            RouteInfo::new(
                1,
                "192.168.1.0".parse().unwrap(),
                33,
                1,
            )
            .is_none()
        );

        assert!(
            RouteInfo::new(
                2,
                "2001:db8::".parse().unwrap(),
                129,
                1,
            )
            .is_none()
        );
    }

    #[test]
    fn rejects_wrong_gateway_family() {
        let route = RouteInfo::new(
            1,
            "192.168.1.0".parse().unwrap(),
            24,
            1,
        )
        .unwrap();

        assert!(
            route
                .with_gateway(
                    "2001:db8::1"
                        .parse()
                        .unwrap()
                )
                .is_none()
        );
    }

    #[test]
    fn accepts_matching_gateway() {
        let route = RouteInfo::new(
            1,
            "192.168.1.0".parse().unwrap(),
            24,
            1,
        )
        .unwrap()
        .with_gateway(
            "192.168.1.1".parse().unwrap()
        )
        .unwrap();

        assert_eq!(
            route.gateway,
            Some(
                "192.168.1.1"
                    .parse()
                    .unwrap()
            )
        );
    }

    #[test]
    fn detects_default_route() {
        let route = RouteInfo::new(
            1,
            "0.0.0.0".parse().unwrap(),
            0,
            1,
        )
        .unwrap();

        assert!(route.is_default());

        assert!(
            route.contains(
                "8.8.8.8".parse().unwrap()
            )
        );
    }

    #[test]
    fn calculates_ipv4_prefix() {
        let route = RouteInfo::new(
            1,
            "192.168.1.123".parse().unwrap(),
            24,
            1,
        )
        .unwrap();

        assert_eq!(
            route.network_prefix(),
            "192.168.1.0"
                .parse::<std::net::IpAddr>()
                .unwrap()
        );
    }

    #[test]
    fn calculates_ipv6_prefix() {
        let route = RouteInfo::new(
            1,
            "2001:db8:1234:5678::10"
                .parse()
                .unwrap(),
            64,
            1,
        )
        .unwrap();

        assert_eq!(
            route.network_prefix(),
            "2001:db8:1234:5678::"
                .parse::<std::net::IpAddr>()
                .unwrap()
        );
    }

    #[test]
    fn contains_ipv4_destination() {
        let route = RouteInfo::new(
            1,
            "10.0.0.0".parse().unwrap(),
            8,
            1,
        )
        .unwrap();

        assert!(
            route.contains(
                "10.20.30.40"
                    .parse()
                    .unwrap()
            )
        );

        assert!(
            !route.contains(
                "11.20.30.40"
                    .parse()
                    .unwrap()
            )
        );
    }

    #[test]
    fn contains_ipv6_destination() {
        let route = RouteInfo::new(
            1,
            "2001:db8:1::"
                .parse()
                .unwrap(),
            64,
            1,
        )
        .unwrap();

        assert!(
            route.contains(
                "2001:db8:1::100"
                    .parse()
                    .unwrap()
            )
        );

        assert!(
            !route.contains(
                "2001:db8:2::100"
                    .parse()
                    .unwrap()
            )
        );
    }

    #[test]
    fn different_ip_versions_do_not_match() {
        let route = RouteInfo::new(
            1,
            "192.168.1.0".parse().unwrap(),
            24,
            1,
        )
        .unwrap();

        assert!(
            !route.contains(
                "2001:db8::1"
                    .parse()
                    .unwrap()
            )
        );
    }

    #[test]
    fn route_type_helpers() {
        assert!(
            RouteType::Unicast.is_forwarding()
        );

        assert!(
            !RouteType::Blackhole.is_forwarding()
        );

        assert!(
            RouteType::Blackhole.is_terminal()
        );

        assert!(
            RouteType::Unreachable.is_terminal()
        );

        assert!(
            RouteType::Prohibit.is_terminal()
        );
    }

    #[test]
    fn disabled_route_is_not_usable() {
        let route = RouteInfo::new(
            1,
            "10.0.0.0".parse().unwrap(),
            8,
            1,
        )
        .unwrap()
        .with_enabled(false);

        assert!(!route.is_usable());
    }

    #[test]
    fn display_contains_route_information() {
        let route = RouteInfo::new(
            1,
            "10.0.0.0".parse().unwrap(),
            8,
            5,
        )
        .unwrap()
        .with_metric(10);

        let text = route.to_string();

        assert!(text.contains("10.0.0.0/8"));
        assert!(text.contains("if=5"));
        assert!(text.contains("metric=10"));
    }
}