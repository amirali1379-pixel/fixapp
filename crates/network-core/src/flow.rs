use std::net::IpAddr;

use crate::timestamp::{TimeDelta, Timestamp};
use crate::Direction;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
}

impl FlowKey {
    pub fn normalized(
        addr1: IpAddr,
        port1: u16,
        addr2: IpAddr,
        port2: u16,
        protocol: Protocol,
    ) -> Self {
        let first = endpoint_sort_key(addr1, port1);
        let second = endpoint_sort_key(addr2, port2);
        let (src_ip, src_port, dst_ip, dst_port) = if first <= second {
            (addr1, port1, addr2, port2)
        } else {
            (addr2, port2, addr1, port1)
        };
        Self { src_ip, dst_ip, src_port, dst_port, protocol }
    }
}

fn endpoint_sort_key(address: IpAddr, port: u16) -> (u8, [u8; 16], u16) {
    match address {
        IpAddr::V4(value) => {
            let octets = value.octets();
            let mut bytes = [0u8; 16];
            bytes[12..].copy_from_slice(&octets);
            (4, bytes, port)
        }
        IpAddr::V6(value) => (6, value.octets(), port),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    IcmpV6,
    Other(u8),
}

impl Protocol {
    pub const fn from_ip_protocol(proto: u8) -> Self {
        match proto {
            1 => Self::Icmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            58 => Self::IcmpV6,
            other => Self::Other(other),
        }
    }

    pub const fn to_ip_protocol(self) -> u8 {
        match self {
            Self::Icmp => 1,
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::IcmpV6 => 58,
            Self::Other(p) => p,
        }
    }

    pub const fn is_tcp(self) -> bool {
        matches!(self, Self::Tcp)
    }

    pub const fn is_udp(self) -> bool {
        matches!(self, Self::Udp)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TcpFlowState {
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    Closing,
    TimeWait,
    Closed,
    Reset,
}

impl TcpFlowState {
    pub const fn is_established(self) -> bool {
        matches!(self, Self::Established)
    }

    pub const fn is_closing(self) -> bool {
        matches!(
            self,
            Self::FinWait1
                | Self::FinWait2
                | Self::Closing
                | Self::TimeWait
        )
    }

    pub const fn is_closed(self) -> bool {
        matches!(self, Self::Closed | Self::Reset)
    }

    pub const fn can_receive(self) -> bool {
        matches!(
            self,
            Self::SynReceived
                | Self::Established
                | Self::FinWait1
                | Self::FinWait2
        )
    }

    pub const fn can_transition_to(self, next: Self) -> bool {
        if matches!(
            (self, next),
            (Self::SynSent, Self::SynSent)
                | (Self::SynReceived, Self::SynReceived)
                | (Self::Established, Self::Established)
                | (Self::FinWait1, Self::FinWait1)
                | (Self::FinWait2, Self::FinWait2)
                | (Self::Closing, Self::Closing)
                | (Self::TimeWait, Self::TimeWait)
                | (Self::Closed, Self::Closed)
                | (Self::Reset, Self::Reset)
        ) {
            return true;
        }

        matches!(
            (self, next),
            (Self::SynSent, Self::SynReceived)
                | (Self::SynSent, Self::Established)
                | (Self::SynSent, Self::Closed)
                | (Self::SynSent, Self::Reset)
                | (Self::SynReceived, Self::Established)
                | (Self::SynReceived, Self::FinWait1)
                | (Self::SynReceived, Self::Closed)
                | (Self::SynReceived, Self::Reset)
                | (Self::Established, Self::FinWait1)
                | (Self::Established, Self::Closed)
                | (Self::Established, Self::Reset)
                | (Self::FinWait1, Self::FinWait2)
                | (Self::FinWait1, Self::Closing)
                | (Self::FinWait1, Self::TimeWait)
                | (Self::FinWait1, Self::Closed)
                | (Self::FinWait1, Self::Reset)
                | (Self::FinWait2, Self::TimeWait)
                | (Self::FinWait2, Self::Closed)
                | (Self::FinWait2, Self::Reset)
                | (Self::Closing, Self::TimeWait)
                | (Self::Closing, Self::Closed)
                | (Self::Closing, Self::Reset)
                | (Self::TimeWait, Self::Closed)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GenericFlowState {
    New,
    Active,
    Idle,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowState {
    Tcp(TcpFlowState),
    Generic(GenericFlowState),
}

impl FlowState {
    pub const fn new_tcp() -> Self {
        Self::Tcp(TcpFlowState::SynSent)
    }

    pub const fn new_generic() -> Self {
        Self::Generic(GenericFlowState::New)
    }

    pub const fn is_established(&self) -> bool {
        matches!(self, Self::Tcp(s) if s.is_established())
            || matches!(self, Self::Generic(GenericFlowState::Active))
    }

    pub const fn is_closed(&self) -> bool {
        matches!(self, Self::Tcp(s) if s.is_closed())
            || matches!(self, Self::Generic(GenericFlowState::Expired))
    }
}

#[derive(Debug, Clone)]
pub struct Flow {
    pub key: FlowKey,
    pub packet_count: u64,
    pub byte_count: u64,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    pub direction: Direction,
    pub state: FlowState,
    pub idle_timeout: TimeDelta,
}

impl Flow {
    pub fn new(key: FlowKey, direction: Direction, packet_bytes: u64) -> Self {
        let now = Timestamp::now();
        Self {
            key,
            packet_count: 1,
            byte_count: packet_bytes,
            first_seen: now,
            last_seen: now,
            direction,
            state: FlowState::new_generic(),
            idle_timeout: TimeDelta::from_secs(300),
        }
    }

    pub fn new_tcp(key: FlowKey, direction: Direction, packet_bytes: u64) -> Self {
        let mut flow = Self::new(key, direction, packet_bytes);
        flow.state = FlowState::new_tcp();
        flow.idle_timeout = TimeDelta::from_secs(7200);
        flow
    }

    pub fn add_packet(&mut self, bytes: u64) {
        self.packet_count = self.packet_count.saturating_add(1);
        self.byte_count = self.byte_count.saturating_add(bytes);
        self.last_seen = Timestamp::now();
    }

    pub fn is_expired(&self, now: Timestamp) -> bool {
        match now.duration_since(self.last_seen) {
            Some(elapsed) => elapsed >= self.idle_timeout.into(),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_key_fields_exist() {
        let key = FlowKey { src_ip: "192.168.1.1".parse().unwrap(), dst_ip: "10.0.0.1".parse().unwrap(), src_port: 12345, dst_port: 80, protocol: Protocol::Tcp };
        assert_eq!(key.src_port, 12345);
        assert_eq!(key.dst_port, 80);
        assert!(key.protocol.is_tcp());
    }

    #[test]
    fn protocol_conversion() {
        assert_eq!(Protocol::Tcp.to_ip_protocol(), 6);
        assert_eq!(Protocol::Udp.to_ip_protocol(), 17);
        assert_eq!(Protocol::Icmp.to_ip_protocol(), 1);
        assert_eq!(Protocol::IcmpV6.to_ip_protocol(), 58);
        assert_eq!(Protocol::from_ip_protocol(6), Protocol::Tcp);
        assert_eq!(Protocol::from_ip_protocol(17), Protocol::Udp);
    }

    #[test]
    fn tcp_state_transitions() {
        assert!(TcpFlowState::SynSent.can_transition_to(TcpFlowState::Established));
        assert!(TcpFlowState::Established.can_transition_to(TcpFlowState::FinWait1));
        assert!(TcpFlowState::FinWait1.can_transition_to(TcpFlowState::FinWait2));
        assert!(TcpFlowState::FinWait2.can_transition_to(TcpFlowState::TimeWait));
        assert!(TcpFlowState::TimeWait.can_transition_to(TcpFlowState::Closed));
        assert!(!TcpFlowState::Closed.can_transition_to(TcpFlowState::Established));
    }

    #[test]
    fn closed_and_reset_states_do_not_reopen() {
        assert!(!TcpFlowState::Closed.can_transition_to(TcpFlowState::SynSent));
        assert!(!TcpFlowState::Reset.can_transition_to(TcpFlowState::SynSent));
    }

    #[test]
    fn fin_wait_2_can_receive() {
        assert!(TcpFlowState::FinWait2.can_receive());
    }

    #[test]
    fn flow_counters_increment() {
        let key = FlowKey { src_ip: "192.168.1.1".parse().unwrap(), dst_ip: "10.0.0.1".parse().unwrap(), src_port: 12345, dst_port: 80, protocol: Protocol::Tcp };
        let mut flow = Flow::new_tcp(key, Direction::Inbound, 100);
        assert_eq!(flow.packet_count, 1);
        assert_eq!(flow.byte_count, 100);
        flow.add_packet(50);
        assert_eq!(flow.packet_count, 2);
        assert_eq!(flow.byte_count, 150);
    }

    #[test]
    fn bidirectional_normalization() {
        let key1 = FlowKey::normalized("192.168.1.1".parse().unwrap(), 12345, "10.0.0.1".parse().unwrap(), 80, Protocol::Tcp);
        let key2 = FlowKey::normalized("10.0.0.1".parse().unwrap(), 80, "192.168.1.1".parse().unwrap(), 12345, Protocol::Tcp);
        assert_eq!(key1, key2);
    }

    #[test]
    fn same_address_different_ports_normalize_by_port() {
        let key1 = FlowKey::normalized("10.0.0.1".parse().unwrap(), 5000, "10.0.0.1".parse().unwrap(), 80, Protocol::Tcp);
        let key2 = FlowKey::normalized("10.0.0.1".parse().unwrap(), 80, "10.0.0.1".parse().unwrap(), 5000, Protocol::Tcp);
        assert_eq!(key1, key2);
    }

    #[test]
    fn expiry_is_true_at_exact_timeout() {
        let key = FlowKey { src_ip: "192.168.1.1".parse().unwrap(), dst_ip: "10.0.0.1".parse().unwrap(), src_port: 12345, dst_port: 80, protocol: Protocol::Tcp };
        let mut flow = Flow::new(key, Direction::Inbound, 100);
        flow.last_seen = Timestamp::from_nanos(1_000);
        flow.idle_timeout = TimeDelta::from_nanos(500);

        assert!(flow.is_expired(Timestamp::from_nanos(1_500)));
    }
}
