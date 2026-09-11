// crates/backend-iphelper/src/neighbors.rs

use std::collections::HashSet;
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;
use std::time::{Duration, SystemTime};

use crate::sockaddr::{SOCKADDR_IN, SOCKADDR_IN6};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeighborState {
    Unreachable,
    Incomplete,
    Probe,
    Delay,
    Stale,
    Reachable,
    Permanent,
    Unknown,
}

impl NeighborState {
    pub fn is_usable(self) -> bool {
        matches!(
            self,
            Self::Reachable | Self::Stale | Self::Permanent
        )
    }

    pub fn is_failed(self) -> bool {
        matches!(self, Self::Unreachable)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NeighborKey {
    pub address: IpAddr,
    pub interface_index: u32,
}

impl NeighborKey {
    pub fn new(
        address: IpAddr,
        interface_index: u32,
    ) -> Option<Self> {
        if interface_index == 0 {
            return None;
        }

        Some(Self {
            address,
            interface_index,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighborInfo {
    pub key: NeighborKey,
    pub mac_address: Option<[u8; 6]>,
    pub state: NeighborState,
    pub updated_at: SystemTime,
}

impl NeighborInfo {
    pub fn new(
        address: IpAddr,
        interface_index: u32,
        mac_address: Option<[u8; 6]>,
        state: NeighborState,
    ) -> Option<Self> {
        let key = NeighborKey::new(address, interface_index)?;

        Some(Self {
            key,
            mac_address,
            state,
            updated_at: SystemTime::now(),
        })
    }

    pub fn address(&self) -> IpAddr {
        self.key.address
    }

    pub fn interface_index(&self) -> u32 {
        self.key.interface_index
    }

    pub fn has_mac(&self) -> bool {
        self.mac_address.is_some()
    }

    pub fn is_usable(&self) -> bool {
        self.state.is_usable() && self.mac_address.is_some()
    }

    pub fn age(&self) -> Duration {
        SystemTime::now()
            .duration_since(self.updated_at)
            .unwrap_or_default()
    }

    pub fn touch(&mut self) {
        self.updated_at = SystemTime::now();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NeighborTableError {
    InvalidInterface,
    NeighborNotFound,
    SystemError(i32),
}

#[derive(Debug, Default)]
pub struct NeighborTable {
    neighbors: Vec<NeighborInfo>,
}

impl NeighborTable {
    pub fn new() -> Self {
        Self {
            neighbors: Vec::new(),
        }
    }

    pub fn insert(
        &mut self,
        neighbor: NeighborInfo,
    ) -> Result<(), NeighborTableError> {
        if neighbor.interface_index() == 0 {
            return Err(NeighborTableError::InvalidInterface);
        }

        if let Some(existing) = self
            .neighbors
            .iter_mut()
            .find(|entry| entry.key == neighbor.key)
        {
            *existing = neighbor;
            return Ok(());
        }

        self.neighbors.push(neighbor);

        Ok(())
    }

    pub fn get(
        &self,
        address: IpAddr,
        interface_index: u32,
    ) -> Result<&NeighborInfo, NeighborTableError> {
        if interface_index == 0 {
            return Err(NeighborTableError::InvalidInterface);
        }

        self.neighbors
            .iter()
            .find(|entry| {
                entry.address() == address
                    && entry.interface_index() == interface_index
            })
            .ok_or(NeighborTableError::NeighborNotFound)
    }

    pub fn get_mut(
        &mut self,
        address: IpAddr,
        interface_index: u32,
    ) -> Result<&mut NeighborInfo, NeighborTableError> {
        if interface_index == 0 {
            return Err(NeighborTableError::InvalidInterface);
        }

        self.neighbors
            .iter_mut()
            .find(|entry| {
                entry.address() == address
                    && entry.interface_index() == interface_index
            })
            .ok_or(NeighborTableError::NeighborNotFound)
    }

    pub fn update_state(
        &mut self,
        address: IpAddr,
        interface_index: u32,
        state: NeighborState,
    ) -> Result<(), NeighborTableError> {
        let neighbor = self.get_mut(address, interface_index)?;

        neighbor.state = state;
        neighbor.touch();

        Ok(())
    }

    pub fn update_mac(
        &mut self,
        address: IpAddr,
        interface_index: u32,
        mac_address: [u8; 6],
    ) -> Result<(), NeighborTableError> {
        let neighbor = self.get_mut(address, interface_index)?;

        neighbor.mac_address = Some(mac_address);
        neighbor.touch();

        Ok(())
    }

    pub fn resolve(
        &self,
        address: IpAddr,
        interface_index: u32,
    ) -> Result<[u8; 6], NeighborTableError> {
        let neighbor = self.get(address, interface_index)?;

        if !neighbor.is_usable() {
            return Err(NeighborTableError::NeighborNotFound);
        }

        neighbor
            .mac_address
            .ok_or(NeighborTableError::NeighborNotFound)
    }

    pub fn remove(
        &mut self,
        address: IpAddr,
        interface_index: u32,
    ) -> Result<NeighborInfo, NeighborTableError> {
        if interface_index == 0 {
            return Err(NeighborTableError::InvalidInterface);
        }

        let position = self
            .neighbors
            .iter()
            .position(|entry| {
                entry.address() == address
                    && entry.interface_index() == interface_index
            })
            .ok_or(NeighborTableError::NeighborNotFound)?;

        Ok(self.neighbors.remove(position))
    }

    pub fn remove_expired(&mut self, max_age: Duration) -> usize {
        let before = self.neighbors.len();

        self.neighbors
            .retain(|neighbor| neighbor.age() <= max_age);

        before - self.neighbors.len()
    }

    pub fn all(&self) -> &[NeighborInfo] {
        &self.neighbors
    }

    pub fn clear(&mut self) {
        self.neighbors.clear();
    }

    pub fn len(&self) -> usize {
        self.neighbors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.neighbors.is_empty()
    }

    #[cfg(windows)]
    pub fn refresh_all(&mut self) -> Result<(), NeighborTableError> {
        let mut current_keys = HashSet::new();

        self.fetch_ipnet(sys::AF_INET, &mut current_keys)?;
        self.fetch_ipnet(sys::AF_INET6, &mut current_keys)?;

        self.neighbors
            .retain(|n| current_keys.contains(&n.key));

        Ok(())
    }

    #[cfg(windows)]
    fn fetch_ipnet(
        &mut self,
        family: u32,
        current_keys: &mut HashSet<NeighborKey>,
    ) -> Result<(), NeighborTableError> {
        let mut table_ptr: *mut sys::MIB_IPNET_TABLE2 = ptr::null_mut();

        unsafe {
            let ret = sys::GetIpNetTable2(family, &mut table_ptr);

            if ret != 0 {
                return Err(NeighborTableError::SystemError(ret as i32));
            }

            if table_ptr.is_null() {
                return Ok(());
            }

            let table = &*table_ptr;
            let entries = std::slice::from_raw_parts(
                table.Row.as_ptr(),
                table.NumEntries as usize,
            );

            for row in entries {
                let address = sys::parse_sockaddr_inet(&row.Address);

                if let Some(addr) = address {
                    if row.InterfaceIndex != 0 {
                        let state = sys::map_neighbor_state(row.State);
                        let mac = if row.PhysicalAddressLength >= 6 {
                            let mut m = [0u8; 6];
                            m.copy_from_slice(&row.PhysicalAddress[..6]);
                            Some(m)
                        } else {
                            None
                        };

                        if let Some(key) = NeighborKey::new(addr, row.InterfaceIndex) {
                            let info = NeighborInfo {
                                key: key.clone(),
                                mac_address: mac,
                                state,
                                updated_at: SystemTime::now(),
                            };

                            self.insert(info)?;
                            current_keys.insert(key);
                        }
                    }
                }
            }

            sys::FreeMibTable(table_ptr as *mut c_void);
        }

        Ok(())
    }
}

#[cfg(windows)]
mod sys {
    use super::*;

    pub const AF_INET: u32 = 2;
    pub const AF_INET6: u32 = 23;

    pub const NlnsUnreachable: u32 = 0;
    pub const NlnsIncomplete: u32 = 1;
    pub const NlnsProbe: u32 = 2;
    pub const NlnsDelay: u32 = 3;
    pub const NlnsStale: u32 = 4;
    pub const NlnsReachable: u32 = 5;
    pub const NlnsPermanent: u32 = 6;
    pub const NlnsMaximum: u32 = 7;

    const SOCKADDR_INET_LEN: usize = 28;

    #[repr(C)]
    pub struct MIB_IPNET_ROW2 {
        pub Address: [u8; SOCKADDR_INET_LEN],
        pub InterfaceLuid: u64,
        pub InterfaceIndex: u32,
        pub PhysicalAddress: [u8; 32],
        pub PhysicalAddressLength: u32,
        pub State: u32,
        pub LastReachable: u64,
        pub ReachabilityTime: u32,
        pub SitePrefixLength: u8,
    }

    #[repr(C)]
    pub struct MIB_IPNET_TABLE2 {
        pub NumEntries: u32,
        pub Row: [MIB_IPNET_ROW2; 1],
    }

    #[link(name = "iphlpapi")]
    extern "system" {
        pub fn GetIpNetTable2(
            Family: u32,
            Table: *mut *mut MIB_IPNET_TABLE2,
        ) -> u32;

        pub fn FreeMibTable(Memory: *mut c_void);
    }

    pub fn map_neighbor_state(state: u32) -> NeighborState {
        match state {
            NlnsUnreachable => NeighborState::Unreachable,
            NlnsIncomplete => NeighborState::Incomplete,
            NlnsProbe => NeighborState::Probe,
            NlnsDelay => NeighborState::Delay,
            NlnsStale => NeighborState::Stale,
            NlnsReachable => NeighborState::Reachable,
            NlnsPermanent => NeighborState::Permanent,
            _ => NeighborState::Unknown,
        }
    }

    pub unsafe fn parse_sockaddr_inet(
        buffer: &[u8; SOCKADDR_INET_LEN],
    ) -> Option<IpAddr> {
        let family = u16::from_ne_bytes([buffer[0], buffer[1]]);

        match u32::from(family) {
            AF_INET => {
                let sin = &*(buffer.as_ptr() as *const SOCKADDR_IN);
                let s_addr = u32::from_be(sin.addr_u32());
                Some(IpAddr::V4(Ipv4Addr::from(s_addr)))
            }
            AF_INET6 => {
                let sin6 = &*(buffer.as_ptr() as *const SOCKADDR_IN6);
                Some(IpAddr::V6(Ipv6Addr::from(sin6.addr_bytes())))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn address() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))
    }

    #[test]
    fn creates_neighbor() {
        let neighbor = NeighborInfo::new(
            address(),
            1,
            Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            NeighborState::Reachable,
        );

        assert!(neighbor.is_some());
    }

    #[test]
    fn invalid_interface_is_rejected() {
        let neighbor = NeighborInfo::new(
            address(),
            0,
            None,
            NeighborState::Unknown,
        );

        assert!(neighbor.is_none());
    }

    #[test]
    fn insert_and_get_neighbor() {
        let mut table = NeighborTable::new();

        let neighbor = NeighborInfo::new(
            address(),
            1,
            Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            NeighborState::Reachable,
        )
        .unwrap();

        table.insert(neighbor).unwrap();

        let found = table.get(address(), 1).unwrap();

        assert_eq!(found.interface_index(), 1);
        assert!(found.has_mac());
    }

    #[test]
    fn resolve_returns_mac() {
        let mut table = NeighborTable::new();

        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        table
            .insert(
                NeighborInfo::new(
                    address(),
                    2,
                    Some(mac),
                    NeighborState::Reachable,
                )
                .unwrap(),
            )
            .unwrap();

        assert_eq!(table.resolve(address(), 2).unwrap(), mac);
    }

    #[test]
    fn stale_neighbor_with_mac_is_usable() {
        let neighbor = NeighborInfo::new(
            address(),
            1,
            Some([0, 1, 2, 3, 4, 5]),
            NeighborState::Stale,
        )
        .unwrap();

        assert!(neighbor.is_usable());
    }

    #[test]
    fn incomplete_neighbor_is_not_usable() {
        let neighbor = NeighborInfo::new(
            address(),
            1,
            None,
            NeighborState::Incomplete,
        )
        .unwrap();

        assert!(!neighbor.is_usable());
    }

    #[test]
    fn state_can_be_updated() {
        let mut table = NeighborTable::new();

        table
            .insert(
                NeighborInfo::new(
                    address(),
                    1,
                    None,
                    NeighborState::Incomplete,
                )
                .unwrap(),
            )
            .unwrap();

        table
            .update_state(address(), 1, NeighborState::Reachable)
            .unwrap();

        assert_eq!(
            table.get(address(), 1).unwrap().state,
            NeighborState::Reachable
        );
    }

    #[test]
    fn mac_can_be_updated() {
        let mut table = NeighborTable::new();

        table
            .insert(
                NeighborInfo::new(
                    address(),
                    1,
                    None,
                    NeighborState::Stale,
                )
                .unwrap(),
            )
            .unwrap();

        let mac = [1, 2, 3, 4, 5, 6];

        table.update_mac(address(), 1, mac).unwrap();

        assert_eq!(
            table.get(address(), 1).unwrap().mac_address,
            Some(mac)
        );
    }

    #[test]
    fn remove_neighbor() {
        let mut table = NeighborTable::new();

        table
            .insert(
                NeighborInfo::new(
                    address(),
                    1,
                    None,
                    NeighborState::Unknown,
                )
                .unwrap(),
            )
            .unwrap();

        let removed = table.remove(address(), 1);
        assert!(removed.is_ok());
        assert!(table.is_empty());
    }

    #[test]
    fn missing_neighbor_returns_error() {
        let table = NeighborTable::new();

        assert_eq!(
            table.get(address(), 1).unwrap_err(),
            NeighborTableError::NeighborNotFound
        );
    }
}