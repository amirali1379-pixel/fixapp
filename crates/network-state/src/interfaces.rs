#![forbid(unsafe_code)]

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum InterfaceKind {
    Unknown = 0,
    Ethernet = 1,
    Wifi = 2,
    Loopback = 3,
    Tunnel = 4,
    Virtual = 5,
    Other = 6,
}

impl InterfaceKind {
    pub fn is_physical(self) -> bool {
        matches!(self, Self::Ethernet | Self::Wifi)
    }

    pub fn is_virtual(self) -> bool {
        matches!(
            self,
            Self::Tunnel | Self::Virtual | Self::Loopback
        )
    }
}

impl fmt::Display for InterfaceKind {
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        let value = match self {
            Self::Unknown => "unknown",
            Self::Ethernet => "ethernet",
            Self::Wifi => "wifi",
            Self::Loopback => "loopback",
            Self::Tunnel => "tunnel",
            Self::Virtual => "virtual",
            Self::Other => "other",
        };

        f.write_str(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum InterfaceState {
    Unknown = 0,
    Down = 1,
    Up = 2,
    Dormant = 3,
    Testing = 4,
}

impl InterfaceState {
    pub fn is_up(self) -> bool {
        self == Self::Up
    }

    pub fn is_operational(self) -> bool {
        matches!(
            self,
            Self::Up | Self::Dormant
        )
    }

    pub fn is_down(self) -> bool {
        self == Self::Down
    }
}

impl fmt::Display for InterfaceState {
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        let value = match self {
            Self::Unknown => "unknown",
            Self::Down => "down",
            Self::Up => "up",
            Self::Dormant => "dormant",
            Self::Testing => "testing",
        };

        f.write_str(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceInfo {
    pub id: u64,
    pub name: String,
    pub description: String,
    pub kind: InterfaceKind,
    pub state: InterfaceState,
    pub mtu: u32,
    pub mac_address: Option<[u8; 6]>,
    pub if_index: Option<u32>,
    pub luid: Option<u64>,
}

impl InterfaceInfo {
    pub fn new(
        id: u64,
        name: impl Into<String>,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            description: String::new(),
            kind: InterfaceKind::Unknown,
            state: InterfaceState::Unknown,
            mtu: 1500,
            mac_address: None,
            if_index: None,
            luid: None,
        }
    }

    pub fn with_description(
        mut self,
        description: impl Into<String>,
    ) -> Self {
        self.description = description.into();
        self
    }

    pub fn with_kind(
        mut self,
        kind: InterfaceKind,
    ) -> Self {
        self.kind = kind;
        self
    }

    pub fn with_state(
        mut self,
        state: InterfaceState,
    ) -> Self {
        self.state = state;
        self
    }

    pub fn with_mtu(
        mut self,
        mtu: u32,
    ) -> Option<Self> {
        if mtu == 0 {
            return None;
        }

        self.mtu = mtu;
        Some(self)
    }

    pub fn with_mac(
        mut self,
        mac: [u8; 6],
    ) -> Self {
        self.mac_address = Some(mac);
        self
    }

    pub fn with_if_index(
        mut self,
        index: u32,
    ) -> Self {
        self.if_index = Some(index);
        self
    }

    pub fn with_luid(
        mut self,
        luid: u64,
    ) -> Self {
        self.luid = Some(luid);
        self
    }

    pub fn is_up(&self) -> bool {
        self.state.is_up()
    }

    pub fn is_operational(&self) -> bool {
        self.state.is_operational()
    }

    pub fn is_loopback(&self) -> bool {
        self.kind == InterfaceKind::Loopback
    }

    pub fn is_physical(&self) -> bool {
        self.kind.is_physical()
    }

    pub fn is_virtual(&self) -> bool {
        self.kind.is_virtual()
    }
}

impl fmt::Display for InterfaceInfo {
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        write!(
            f,
            "{} ({}, {})",
            self.name,
            self.kind,
            self.state
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_interface() {
        let interface =
            InterfaceInfo::new(1, "Ethernet");

        assert_eq!(interface.id, 1);
        assert_eq!(interface.name, "Ethernet");
        assert_eq!(
            interface.kind,
            InterfaceKind::Unknown
        );
        assert_eq!(
            interface.state,
            InterfaceState::Unknown
        );
        assert_eq!(interface.mtu, 1500);
    }

    #[test]
    fn interface_builder() {
        let interface = InterfaceInfo::new(
            10,
            "Wi-Fi",
        )
        .with_description("Wireless adapter")
        .with_kind(InterfaceKind::Wifi)
        .with_state(InterfaceState::Up)
        .with_mac([1, 2, 3, 4, 5, 6])
        .with_if_index(7)
        .with_luid(12345);

        assert_eq!(
            interface.kind,
            InterfaceKind::Wifi
        );

        assert_eq!(
            interface.state,
            InterfaceState::Up
        );

        assert!(interface.is_up());
        assert!(interface.is_operational());
        assert!(interface.is_physical());

        assert_eq!(
            interface.mac_address,
            Some([1, 2, 3, 4, 5, 6])
        );

        assert_eq!(
            interface.if_index,
            Some(7)
        );

        assert_eq!(
            interface.luid,
            Some(12345)
        );
    }

    #[test]
    fn rejects_zero_mtu() {
        let interface =
            InterfaceInfo::new(1, "Ethernet");

        assert!(
            interface.with_mtu(0).is_none()
        );
    }

    #[test]
    fn accepts_valid_mtu() {
        let interface =
            InterfaceInfo::new(1, "Ethernet")
                .with_mtu(9000)
                .unwrap();

        assert_eq!(interface.mtu, 9000);
    }

    #[test]
    fn interface_kind_helpers() {
        assert!(
            InterfaceKind::Ethernet.is_physical()
        );

        assert!(
            InterfaceKind::Wifi.is_physical()
        );

        assert!(
            InterfaceKind::Virtual.is_virtual()
        );

        assert!(
            InterfaceKind::Tunnel.is_virtual()
        );

        assert!(
            InterfaceKind::Loopback.is_virtual()
        );
    }

    #[test]
    fn interface_state_helpers() {
        assert!(InterfaceState::Up.is_up());
        assert!(InterfaceState::Up.is_operational());

        assert!(
            InterfaceState::Dormant.is_operational()
        );

        assert!(InterfaceState::Down.is_down());
        assert!(!InterfaceState::Down.is_operational());
    }

    #[test]
    fn display_works() {
        let interface =
            InterfaceInfo::new(1, "Ethernet")
                .with_kind(
                    InterfaceKind::Ethernet
                )
                .with_state(
                    InterfaceState::Up
                );

        assert_eq!(
            interface.to_string(),
            "Ethernet (ethernet, up)"
        );
    }
}