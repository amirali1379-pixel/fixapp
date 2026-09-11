#![forbid(unsafe_code)]

use std::fmt;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: u8,
}

impl FlowKey {
    pub fn new(
        source_ip: IpAddr,
        destination_ip: IpAddr,
        source_port: u16,
        destination_port: u16,
        protocol: u8,
    ) -> Self {
        Self {
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol,
        }
    }

    pub fn reverse(&self) -> Self {
        Self {
            source_ip: self.destination_ip,
            destination_ip: self.source_ip,
            source_port: self.destination_port,
            destination_port: self.source_port,
            protocol: self.protocol,
        }
    }

    pub fn is_reverse_of(&self, other: &Self) -> bool {
        self == &other.reverse()
    }

    pub fn is_ipv4(&self) -> bool {
        self.source_ip.is_ipv4()
            && self.destination_ip.is_ipv4()
    }

    pub fn is_ipv6(&self) -> bool {
        self.source_ip.is_ipv6()
            && self.destination_ip.is_ipv6()
    }

    pub fn is_tcp(&self) -> bool {
        self.protocol == 6
    }

    pub fn is_udp(&self) -> bool {
        self.protocol == 17
    }

    pub fn is_icmp(&self) -> bool {
        self.protocol == 1
    }

    pub fn is_icmpv6(&self) -> bool {
        self.protocol == 58
    }
}

impl fmt::Display for FlowKey {
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{} / {}",
            self.source_ip,
            self.source_port,
            self.destination_ip,
            self.destination_port,
            self.protocol
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_flow_key() {
        let key = FlowKey::new(
            "192.168.1.10"
                .parse()
                .unwrap(),
            "8.8.8.8"
                .parse()
                .unwrap(),
            12345,
            443,
            6,
        );

        assert_eq!(
            key.source_port,
            12345
        );

        assert_eq!(
            key.destination_port,
            443
        );

        assert_eq!(
            key.protocol,
            6
        );
    }

    #[test]
    fn reverse_key_is_correct() {
        let key = FlowKey::new(
            "192.168.1.10"
                .parse()
                .unwrap(),
            "8.8.8.8"
                .parse()
                .unwrap(),
            12345,
            443,
            6,
        );

        let reversed = key.reverse();

        assert_eq!(
            reversed.source_ip,
            "8.8.8.8"
                .parse::<std::net::IpAddr>()
                .unwrap()
        );

        assert_eq!(
            reversed.destination_ip,
            "192.168.1.10"
                .parse::<std::net::IpAddr>()
                .unwrap()
        );

        assert_eq!(
            reversed.source_port,
            443
        );

        assert_eq!(
            reversed.destination_port,
            12345
        );

        assert_eq!(
            reversed.protocol,
            6
        );
    }

    #[test]
    fn detects_reverse_flow() {
        let key = FlowKey::new(
            "10.0.0.1"
                .parse()
                .unwrap(),
            "10.0.0.2"
                .parse()
                .unwrap(),
            5000,
            443,
            6,
        );

        let reverse = FlowKey::new(
            "10.0.0.2"
                .parse()
                .unwrap(),
            "10.0.0.1"
                .parse()
                .unwrap(),
            443,
            5000,
            6,
        );

        assert!(key.is_reverse_of(&reverse));
        assert!(reverse.is_reverse_of(&key));
    }

    #[test]
    fn detects_protocol() {
        let tcp = FlowKey::new(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            1,
            2,
            6,
        );

        let udp = FlowKey::new(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            1,
            2,
            17,
        );

        assert!(tcp.is_tcp());
        assert!(!tcp.is_udp());

        assert!(udp.is_udp());
        assert!(!udp.is_tcp());
    }

    #[test]
    fn detects_ip_version() {
        let ipv4 = FlowKey::new(
            "192.168.1.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            1000,
            443,
            6,
        );

        let ipv6 = FlowKey::new(
            "::1".parse().unwrap(),
            "2001:4860:4860::8888"
                .parse()
                .unwrap(),
            1000,
            443,
            6,
        );

        assert!(ipv4.is_ipv4());
        assert!(!ipv4.is_ipv6());

        assert!(ipv6.is_ipv6());
        assert!(!ipv6.is_ipv4());
    }

    #[test]
    fn equality_and_hashing_work() {
        use std::collections::HashSet;

        let key = FlowKey::new(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            1234,
            5678,
            17,
        );

        let same = key.clone();

        let mut set = HashSet::new();
        set.insert(key);

        assert!(set.contains(&same));
    }
}