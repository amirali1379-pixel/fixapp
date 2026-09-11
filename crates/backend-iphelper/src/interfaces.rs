// crates/backend-iphelper/src/interfaces.rs

use std::ffi::{c_void, CStr, OsString};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::windows::ffi::OsStringExt;
use std::ptr;
use std::slice;

use crate::sockaddr::{SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceType {
    Ethernet,
    Wifi,
    Loopback,
    Tunnel,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceOperationalState {
    Up,
    Down,
    Testing,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceAddress {
    pub address: IpAddr,
    pub prefix_length: u8,
}

impl InterfaceAddress {
    pub fn new(
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
            address,
            prefix_length,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceInfo {
    pub index: u32,
    pub name: String,
    pub description: String,
    pub interface_type: InterfaceType,
    pub operational_state: InterfaceOperationalState,
    pub mtu: u32,
    pub mac_address: Option<[u8; 6]>,
    pub addresses: Vec<InterfaceAddress>,
}

impl InterfaceInfo {
    pub fn new(
        index: u32,
        name: impl Into<String>,
    ) -> Option<Self> {
        if index == 0 {
            return None;
        }

        let name = name.into();

        if name.trim().is_empty() {
            return None;
        }

        Some(Self {
            index,
            name,
            description: String::new(),
            interface_type: InterfaceType::Unknown,
            operational_state:
                InterfaceOperationalState::Unknown,
            mtu: 0,
            mac_address: None,
            addresses: Vec::new(),
        })
    }

    pub fn add_address(
        &mut self,
        address: InterfaceAddress,
    ) {
        if !self
            .addresses
            .iter()
            .any(|existing| existing == &address)
        {
            self.addresses.push(address);
        }
    }

    pub fn is_up(&self) -> bool {
        self.operational_state
            == InterfaceOperationalState::Up
    }

    pub fn has_address_family_v4(&self) -> bool {
        self.addresses.iter().any(|entry| {
            matches!(
                entry.address,
                IpAddr::V4(_)
            )
        })
    }

    pub fn has_address_family_v6(&self) -> bool {
        self.addresses.iter().any(|entry| {
            matches!(
                entry.address,
                IpAddr::V6(_)
            )
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceQueryError {
    InvalidInterfaceIndex,
    InterfaceNotFound,
    SystemError(i32),
}

#[derive(Debug, Default)]
pub struct InterfaceTable {
    interfaces: Vec<InterfaceInfo>,
}

impl InterfaceTable {
    pub fn new() -> Self {
        Self {
            interfaces: Vec::new(),
        }
    }

    pub fn insert(
        &mut self,
        interface: InterfaceInfo,
    ) -> Result<(), InterfaceQueryError> {
        if interface.index == 0 {
            return Err(
                InterfaceQueryError::InvalidInterfaceIndex
            );
        }

        if let Some(existing) = self
            .interfaces
            .iter_mut()
            .find(|entry| {
                entry.index == interface.index
            })
        {
            *existing = interface;
            return Ok(());
        }

        self.interfaces.push(interface);

        Ok(())
    }

    pub fn get(
        &self,
        index: u32,
    ) -> Result<&InterfaceInfo, InterfaceQueryError> {
        if index == 0 {
            return Err(
                InterfaceQueryError::InvalidInterfaceIndex
            );
        }

        self.interfaces
            .iter()
            .find(|entry| entry.index == index)
            .ok_or(
                InterfaceQueryError::InterfaceNotFound
            )
    }

    pub fn remove(
        &mut self,
        index: u32,
    ) -> Result<InterfaceInfo, InterfaceQueryError> {
        if index == 0 {
            return Err(
                InterfaceQueryError::InvalidInterfaceIndex
            );
        }

        let position = self
            .interfaces
            .iter()
            .position(|entry| entry.index == index)
            .ok_or(
                InterfaceQueryError::InterfaceNotFound
            )?;

        Ok(self.interfaces.remove(position))
    }

    pub fn all(&self) -> &[InterfaceInfo] {
        &self.interfaces
    }

    pub fn clear(&mut self) {
        self.interfaces.clear();
    }

    pub fn len(&self) -> usize {
        self.interfaces.len()
    }

    pub fn is_empty(&self) -> bool {
        self.interfaces.is_empty()
    }

    #[cfg(windows)]
    pub fn refresh_all(&mut self) -> Result<(), InterfaceQueryError> {
        let mut size: u32 = 15000;
        let mut retry = 0;

        loop {
            let mut buffer: Vec<u8> = vec![0; size as usize];

            unsafe {
                let ret = sys::GetAdaptersAddresses(
                    sys::AF_UNSPEC,
                    sys::GAA_FLAG_INCLUDE_PREFIX
                        | sys::GAA_FLAG_SKIP_ANYCAST
                        | sys::GAA_FLAG_SKIP_MULTICAST
                        | sys::GAA_FLAG_SKIP_DNS_SERVER,
                    ptr::null_mut(),
                    buffer.as_mut_ptr() as *mut sys::IP_ADAPTER_ADDRESSES_LH,
                    &mut size,
                );

                if ret == sys::ERROR_BUFFER_OVERFLOW && retry < 3 {
                    retry += 1;
                    continue;
                }

                if ret != 0 {
                    return Err(
                        InterfaceQueryError::SystemError(ret as i32)
                    );
                }

                self.parse_adapters(buffer.as_ptr() as *const sys::IP_ADAPTER_ADDRESSES_LH)?;
                break;
            }
        }

        Ok(())
    }

    #[cfg(windows)]
    unsafe fn parse_adapters(
        &mut self,
        ptr: *const sys::IP_ADAPTER_ADDRESSES_LH,
    ) -> Result<(), InterfaceQueryError> {
        self.clear();

        let mut current = ptr;
        while !current.is_null() {
            let adapter = &*current;

            let name = if !adapter.FriendlyName.is_null() {
                os_string_from_wide(adapter.FriendlyName)
                    .unwrap_or_else(|_| String::from("Unknown"))
            } else if !adapter.AdapterName.is_null() {
                let c_str = CStr::from_ptr(adapter.AdapterName as *const i8);
                c_str.to_string_lossy().into_owned()
            } else {
                String::from("Unknown")
            };

            let description = if !adapter.Description.is_null() {
                os_string_from_wide(adapter.Description)
                    .unwrap_or_default()
            } else {
                String::new()
            };

            if let Some(mut info) = InterfaceInfo::new(adapter.IfIndex, name) {
                info.description = description;
                info.mtu = adapter.Mtu;
                info.operational_state = sys::map_oper_status(adapter.OperStatus);
                info.interface_type = sys::map_if_type(adapter.IfType);

                if adapter.PhysicalAddressLength >= 6 {
                    let mut mac = [0u8; 6];
                    mac.copy_from_slice(
                        &slice::from_raw_parts(
                            adapter.PhysicalAddress.as_ptr(),
                            6,
                        ),
                    );
                    info.mac_address = Some(mac);
                }

                let mut addr_ptr = adapter.FirstUnicastAddress;
                while !addr_ptr.is_null() {
                    let unicast = &*addr_ptr;

                    if let Some(sockaddr) = sys::parse_sockaddr(unicast.Address.lpSockaddr) {
                        if let Some(if_addr) = InterfaceAddress::new(
                            sockaddr,
                            unicast.OnLinkPrefixLength,
                        ) {
                            info.add_address(if_addr);
                        }
                    }

                    addr_ptr = unicast.Next;
                }

                self.insert(info)?;
            }

            current = adapter.Next;
        }

        Ok(())
    }
}

#[cfg(windows)]
unsafe fn os_string_from_wide(ptr: *const u16) -> Result<String, ()> {
    if ptr.is_null() {
        return Err(());
    }

    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }

    let slice = slice::from_raw_parts(ptr, len);
    OsString::from_wide(slice)
        .into_string()
        .map_err(|_| ())
}

#[cfg(windows)]
mod sys {
    use super::*;

    pub const AF_UNSPEC: u32 = 0;
    pub const AF_INET: u32 = 2;
    pub const AF_INET6: u32 = 23;

    pub const ERROR_BUFFER_OVERFLOW: u32 = 111;

    pub const GAA_FLAG_INCLUDE_PREFIX: u32 = 0x00000010;
    pub const GAA_FLAG_SKIP_ANYCAST: u32 = 0x00000002;
    pub const GAA_FLAG_SKIP_MULTICAST: u32 = 0x00000004;
    pub const GAA_FLAG_SKIP_DNS_SERVER: u32 = 0x00000008;

    pub const IfOperStatusUp: u32 = 1;
    pub const IfOperStatusDown: u32 = 2;
    pub const IfOperStatusTesting: u32 = 3;

    pub const IF_TYPE_ETHERNET_CSMACD: u32 = 6;
    pub const IF_TYPE_IEEE80211: u32 = 71;
    pub const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
    pub const IF_TYPE_TUNNEL: u32 = 131;

    #[repr(C)]
    pub struct SOCKET_ADDRESS {
        pub lpSockaddr: *mut SOCKADDR,
        pub iSockaddrLength: i32,
    }

    #[repr(C)]
    pub struct IP_ADAPTER_UNICAST_ADDRESS_LH {
        pub Length: u32,
        pub Flags: u32,
        pub Next: *mut IP_ADAPTER_UNICAST_ADDRESS_LH,
        pub Address: SOCKET_ADDRESS,
        pub PrefixOrigin: u32,
        pub SuffixOrigin: u32,
        pub DadState: u32,
        pub ValidLifetime: u32,
        pub PreferredLifetime: u32,
        pub LeaseLifetime: u32,
        pub OnLinkPrefixLength: u8,
    }

    #[repr(C)]
    pub struct IP_ADAPTER_ADDRESSES_LH {
        pub Length: u32,
        pub IfIndex: u32,
        pub Next: *mut IP_ADAPTER_ADDRESSES_LH,
        pub AdapterName: *mut i8,
        pub FirstUnicastAddress: *mut IP_ADAPTER_UNICAST_ADDRESS_LH,
        pub FirstAnycastAddress: *mut c_void,
        pub FirstMulticastAddress: *mut c_void,
        pub FirstDnsServerAddress: *mut c_void,
        pub DnsSuffix: *mut u16,
        pub Description: *mut u16,
        pub FriendlyName: *mut u16,
        pub PhysicalAddress: [u8; 8],
        pub PhysicalAddressLength: u32,
        pub Flags: u32,
        pub Mtu: u32,
        pub IfType: u32,
        pub OperStatus: u32,
        pub Ipv6IfIndex: u32,
        pub ZoneIndices: [u32; 16],
        pub FirstPrefix: *mut c_void,
        pub TransmitLinkSpeed: u64,
        pub ReceiveLinkSpeed: u64,
        pub FirstWinsServerAddress: *mut c_void,
        pub FirstGatewayAddress: *mut c_void,
        pub Ipv4Metric: u32,
        pub Ipv6Metric: u32,
        pub Luid: u64,
        pub Dhcpv4Server: SOCKET_ADDRESS,
        pub CompartmentId: u32,
        pub NetworkGuid: [u8; 16],
        pub ConnectionType: u32,
        pub TunnelType: u32,
    }

    #[link(name = "iphlpapi")]
    extern "system" {
        pub fn GetAdaptersAddresses(
            Family: u32,
            Flags: u32,
            Reserved: *mut c_void,
            AdapterAddresses: *mut IP_ADAPTER_ADDRESSES_LH,
            SizePointer: *mut u32,
        ) -> u32;
    }

    pub fn map_oper_status(status: u32) -> InterfaceOperationalState {
        match status {
            IfOperStatusUp => InterfaceOperationalState::Up,
            IfOperStatusDown => InterfaceOperationalState::Down,
            IfOperStatusTesting => InterfaceOperationalState::Testing,
            _ => InterfaceOperationalState::Unknown,
        }
    }

    pub fn map_if_type(if_type: u32) -> InterfaceType {
        match if_type {
            IF_TYPE_ETHERNET_CSMACD => InterfaceType::Ethernet,
            IF_TYPE_IEEE80211 => InterfaceType::Wifi,
            IF_TYPE_SOFTWARE_LOOPBACK => InterfaceType::Loopback,
            IF_TYPE_TUNNEL => InterfaceType::Tunnel,
            _ => InterfaceType::Unknown,
        }
    }

    pub unsafe fn parse_sockaddr(addr: *const SOCKADDR) -> Option<IpAddr> {
        if addr.is_null() {
            return None;
        }

        let sa = &*addr;

        if sa.sa_family as u32 == AF_INET {
            let sin = &*(addr as *const SOCKADDR_IN);
            let s_addr = u32::from_be(sin.addr_u32());
            Some(IpAddr::V4(Ipv4Addr::from(s_addr)))
        } else if sa.sa_family as u32 == AF_INET6 {
            let sin6 = &*(addr as *const SOCKADDR_IN6);
            Some(IpAddr::V6(Ipv6Addr::from(sin6.addr_bytes())))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn interface() -> InterfaceInfo {
        InterfaceInfo::new(1, "Ethernet").unwrap()
    }

    #[test]
    fn interface_address_validates_prefix() {
        let address = InterfaceAddress::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            24,
        );

        assert!(address.is_some());

        let invalid = InterfaceAddress::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            33,
        );

        assert!(invalid.is_none());
    }

    #[test]
    fn interface_requires_valid_index() {
        assert!(InterfaceInfo::new(0, "Ethernet").is_none());
    }

    #[test]
    fn interface_requires_name() {
        assert!(InterfaceInfo::new(1, "   ").is_none());
    }

    #[test]
    fn address_can_be_added() {
        let mut info = interface();

        let address = InterfaceAddress::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            24,
        )
        .unwrap();

        info.add_address(address.clone());
        info.add_address(address);

        assert_eq!(info.addresses.len(), 1);
        assert!(info.has_address_family_v4());
    }

    #[test]
    fn table_inserts_and_finds_interface() {
        let mut table = InterfaceTable::new();

        table.insert(interface()).unwrap();

        let found = table.get(1).unwrap();

        assert_eq!(found.name, "Ethernet");
    }

    #[test]
    fn duplicate_index_updates_interface() {
        let mut table = InterfaceTable::new();

        table.insert(interface()).unwrap();

        let mut updated =
            InterfaceInfo::new(1, "Updated Ethernet").unwrap();

        updated.mtu = 1500;

        table.insert(updated).unwrap();

        assert_eq!(table.len(), 1);
        assert_eq!(table.get(1).unwrap().name, "Updated Ethernet");
        assert_eq!(table.get(1).unwrap().mtu, 1500);
    }

    #[test]
    fn table_removes_interface() {
        let mut table = InterfaceTable::new();

        table.insert(interface()).unwrap();

        let removed = table.remove(1).unwrap();

        assert_eq!(removed.index, 1);
        assert!(table.is_empty());
    }

    #[test]
    fn missing_interface_returns_error() {
        let table = InterfaceTable::new();

        assert_eq!(
            table.get(1),
            Err(InterfaceQueryError::InterfaceNotFound)
        );
    }
}