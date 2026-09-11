#![forbid(unsafe_code)]

use std::fmt;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum NeighborState {
    Unknown = 0,
    Reachable = 1,
    Stale = 2,
    Delay = 3,
    Probe = 4,
    Failed = 5,
    Incomplete = 6,
    Permanent = 7,
    Unreachable = 8,
}

impl NeighborState {
    pub fn is_reachable(self) -> bool {
        matches!(
            self,
            Self::Reachable | Self::Permanent
        )
    }

    pub fn is_failed(self) -> bool {
        matches!(
            self,
            Self::Failed | Self::Unreachable
        )
    }

    pub fn requires_resolution(self) -> bool {
        matches!(
            self,
            Self::Unknown
                | Self::Incomplete
                | Self::Probe
        )
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Failed | Self::Unreachable
        )
    }
}

impl fmt::Display for NeighborState {
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        let value = match self {
            Self::Unknown => "unknown",
            Self::Reachable => "reachable",
            Self::Stale => "stale",
            Self::Delay => "delay",
            Self::Probe => "probe",
            Self::Failed => "failed",
            Self::Incomplete => "incomplete",
            Self::Permanent => "permanent",
            Self::Unreachable => "unreachable",
        };

        f.write_str(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NeighborInfo {
    pub interface_id: u64,
    pub ip_address: IpAddr,
    pub mac_address: Option<[u8; 6]>,
    pub state: NeighborState,
    pub is_router: bool,
}

impl NeighborInfo {
    pub fn new(
        interface_id: u64,
        ip_address: IpAddr,
    ) -> Self {
        Self {
            interface_id,
            ip_address,
            mac_address: None,
            state: NeighborState::Unknown,
            is_router: false,
        }
    }

    pub fn with_mac(
        mut self,
        mac_address: [u8; 6],
    ) -> Self {
        self.mac_address = Some(mac_address);
        self
    }

    pub fn with_state(
        mut self,
        state: NeighborState,
    ) -> Self {
        self.state = state;
        self
    }

    pub fn with_router(
        mut self,
        is_router: bool,
    ) -> Self {
        self.is_router = is_router;
        self
    }

    pub fn is_ipv4(&self) -> bool {
        self.ip_address.is_ipv4()
    }

    pub fn is_ipv6(&self) -> bool {
        self.ip_address.is_ipv6()
    }

    pub fn is_resolved(&self) -> bool {
        self.mac_address.is_some()
            && self.state.is_reachable()
    }

    pub fn is_usable(&self) -> bool {
        self.mac_address.is_some()
            && !self.state.is_failed()
    }

    pub fn requires_resolution(&self) -> bool {
        self.mac_address.is_none()
            || self.state.requires_resolution()
    }

    pub fn set_mac(
        &mut self,
        mac_address: [u8; 6],
    ) {
        self.mac_address = Some(mac_address);
    }

    pub fn clear_mac(&mut self) {
        self.mac_address = None;
    }

    pub fn mark_reachable(
        &mut self,
        mac_address: [u8; 6],
    ) {
        self.mac_address = Some(mac_address);
        self.state = NeighborState::Reachable;
    }

    pub fn mark_failed(&mut self) {
        self.state = NeighborState::Failed;
    }
}

impl fmt::Display for NeighborInfo {
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        write!(
            f,
            "{} ({})",
            self.ip_address,
            self.state
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_neighbor() {
        let neighbor = NeighborInfo::new(
            1,
            "192.168.1.1".parse().unwrap(),
        );

        assert_eq!(
            neighbor.interface_id,
            1
        );

        assert_eq!(
            neighbor.ip_address,
            "192.168.1.1"
                .parse::<std::net::IpAddr>()
                .unwrap()
        );

        assert_eq!(
            neighbor.state,
            NeighborState::Unknown
        );

        assert!(neighbor.is_ipv4());
        assert!(!neighbor.is_ipv6());
        assert!(neighbor.requires_resolution());
    }

    #[test]
    fn creates_ipv6_neighbor() {
        let neighbor = NeighborInfo::new(
            2,
            "fe80::1".parse().unwrap(),
        );

        assert!(neighbor.is_ipv6());
        assert!(!neighbor.is_ipv4());
    }

    #[test]
    fn reachable_neighbor_is_resolved() {
        let neighbor = NeighborInfo::new(
            1,
            "192.168.1.1".parse().unwrap(),
        )
        .with_mac([0, 1, 2, 3, 4, 5])
        .with_state(NeighborState::Reachable);

        assert!(neighbor.is_resolved());
        assert!(neighbor.is_usable());
        assert!(!neighbor.requires_resolution());
    }

    #[test]
    fn permanent_neighbor_is_reachable() {
        let neighbor = NeighborInfo::new(
            1,
            "192.168.1.1".parse().unwrap(),
        )
        .with_mac([1, 2, 3, 4, 5, 6])
        .with_state(NeighborState::Permanent);

        assert!(neighbor.is_resolved());
        assert!(neighbor.is_usable());
    }

    #[test]
    fn failed_neighbor_is_not_usable() {
        let neighbor = NeighborInfo::new(
            1,
            "192.168.1.1".parse().unwrap(),
        )
        .with_state(NeighborState::Failed);

        assert!(neighbor.state.is_failed());
        assert!(!neighbor.is_usable());
        assert!(neighbor.requires_resolution());
    }

    #[test]
    fn unreachable_neighbor_is_not_usable() {
        let neighbor = NeighborInfo::new(
            1,
            "192.168.1.1".parse().unwrap(),
        )
        .with_state(NeighborState::Unreachable);

        assert!(neighbor.state.is_failed());
        assert!(!neighbor.is_usable());
    }

    #[test]
    fn mark_reachable_updates_neighbor() {
        let mut neighbor = NeighborInfo::new(
            1,
            "10.0.0.1".parse().unwrap(),
        );

        neighbor.mark_reachable(
            [10, 20, 30, 40, 50, 60],
        );

        assert_eq!(
            neighbor.state,
            NeighborState::Reachable
        );

        assert_eq!(
            neighbor.mac_address,
            Some([10, 20, 30, 40, 50, 60])
        );

        assert!(neighbor.is_resolved());
    }

    #[test]
    fn mark_failed_updates_state() {
        let mut neighbor = NeighborInfo::new(
            1,
            "10.0.0.1".parse().unwrap(),
        );

        neighbor.mark_failed();

        assert_eq!(
            neighbor.state,
            NeighborState::Failed
        );

        assert!(neighbor.state.is_failed());
    }

    #[test]
    fn clear_mac_requires_resolution() {
        let mut neighbor = NeighborInfo::new(
            1,
            "10.0.0.1".parse().unwrap(),
        )
        .with_mac([1, 2, 3, 4, 5, 6])
        .with_state(NeighborState::Reachable);

        assert!(neighbor.is_resolved());

        neighbor.clear_mac();

        assert!(!neighbor.is_resolved());
        assert!(neighbor.requires_resolution());
    }

    #[test]
    fn router_flag_works() {
        let neighbor = NeighborInfo::new(
            1,
            "192.168.1.1".parse().unwrap(),
        )
        .with_router(true);

        assert!(neighbor.is_router);
    }

    #[test]
    fn neighbor_state_helpers() {
        assert!(
            NeighborState::Reachable.is_reachable()
        );

        assert!(
            NeighborState::Permanent.is_reachable()
        );

        assert!(
            NeighborState::Incomplete
                .requires_resolution()
        );

        assert!(
            NeighborState::Probe
                .requires_resolution()
        );

        assert!(
            NeighborState::Failed.is_terminal()
        );

        assert!(
            NeighborState::Failed.is_failed()
        );

        assert!(
            NeighborState::Unreachable.is_failed()
        );

        assert!(
            NeighborState::Unreachable.is_terminal()
        );
    }
}