#![forbid(unsafe_code)]

use std::fmt;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum GatewayType {
    Unknown = 0,
    Default = 1,
    Static = 2,
    Dhcp = 3,
    RouterAdvertisement = 4,
    OnLink = 5,
}

impl GatewayType {
    pub fn is_dynamic(self) -> bool {
        matches!(
            self,
            Self::Dhcp | Self::RouterAdvertisement
        )
    }

    pub fn is_static(self) -> bool {
        matches!(
            self,
            Self::Static
        )
    }
}

impl fmt::Display for GatewayType {
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        let value = match self {
            Self::Unknown => "unknown",
            Self::Default => "default",
            Self::Static => "static",
            Self::Dhcp => "dhcp",
            Self::RouterAdvertisement => "router-advertisement",
            Self::OnLink => "on-link",
        };

        f.write_str(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GatewayInfo {
    pub interface_id: u64,
    pub address: IpAddr,
    pub gateway_type: GatewayType,
    pub metric: u32,
    pub reachable: bool,
    pub enabled: bool,
}

impl GatewayInfo {
    pub fn new(
        interface_id: u64,
        address: IpAddr,
    ) -> Self {
        Self {
            interface_id,
            address,
            gateway_type: GatewayType::Unknown,
            metric: 0,
            reachable: false,
            enabled: true,
        }
    }

    pub fn with_type(
        mut self,
        gateway_type: GatewayType,
    ) -> Self {
        self.gateway_type = gateway_type;
        self
    }

    pub fn with_metric(
        mut self,
        metric: u32,
    ) -> Self {
        self.metric = metric;
        self
    }

    pub fn with_reachable(
        mut self,
        reachable: bool,
    ) -> Self {
        self.reachable = reachable;
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
        self.address.is_ipv4()
    }

    pub fn is_ipv6(&self) -> bool {
        self.address.is_ipv6()
    }

    pub fn is_dynamic(&self) -> bool {
        self.gateway_type.is_dynamic()
    }

    pub fn is_static(&self) -> bool {
        self.gateway_type.is_static()
    }

    pub fn is_usable(&self) -> bool {
        self.enabled && self.reachable
    }
}

impl fmt::Display for GatewayInfo {
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        write!(
            f,
            "{} via interface {} ({}, metric={})",
            self.address,
            self.interface_id,
            self.gateway_type,
            self.metric
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_gateway() {
        let gateway = GatewayInfo::new(
            1,
            "192.168.1.1".parse().unwrap(),
        );

        assert_eq!(
            gateway.interface_id,
            1
        );

        assert_eq!(
            gateway.address,
            "192.168.1.1"
                .parse::<std::net::IpAddr>()
                .unwrap()
        );

        assert_eq!(
            gateway.gateway_type,
            GatewayType::Unknown
        );

        assert!(gateway.enabled);
        assert!(!gateway.reachable);
        assert!(!gateway.is_usable());
    }

    #[test]
    fn creates_ipv6_gateway() {
        let gateway = GatewayInfo::new(
            2,
            "fe80::1".parse().unwrap(),
        );

        assert!(gateway.is_ipv6());
        assert!(!gateway.is_ipv4());
    }

    #[test]
    fn reachable_gateway_is_usable() {
        let gateway = GatewayInfo::new(
            1,
            "192.168.1.1".parse().unwrap(),
        )
        .with_type(GatewayType::Dhcp)
        .with_metric(10)
        .with_reachable(true);

        assert!(gateway.is_usable());
        assert!(gateway.is_dynamic());
        assert!(!gateway.is_static());
        assert_eq!(gateway.metric, 10);
    }

    #[test]
    fn disabled_gateway_is_not_usable() {
        let gateway = GatewayInfo::new(
            1,
            "192.168.1.1".parse().unwrap(),
        )
        .with_reachable(true)
        .with_enabled(false);

        assert!(!gateway.is_usable());
    }

    #[test]
    fn static_gateway() {
        let gateway = GatewayInfo::new(
            1,
            "10.0.0.1".parse().unwrap(),
        )
        .with_type(GatewayType::Static);

        assert!(gateway.is_static());
        assert!(!gateway.is_dynamic());
    }

    #[test]
    fn dynamic_gateway_types() {
        assert!(
            GatewayType::Dhcp.is_dynamic()
        );

        assert!(
            GatewayType::RouterAdvertisement
                .is_dynamic()
        );

        assert!(
            !GatewayType::Static.is_dynamic()
        );
    }

    #[test]
    fn display_contains_information() {
        let gateway = GatewayInfo::new(
            5,
            "192.168.1.1".parse().unwrap(),
        )
        .with_type(GatewayType::Static)
        .with_metric(20);

        let text = gateway.to_string();

        assert!(
            text.contains("192.168.1.1")
        );
        assert!(
            text.contains("interface 5")
        );
        assert!(
            text.contains("metric=20")
        );
    }
}