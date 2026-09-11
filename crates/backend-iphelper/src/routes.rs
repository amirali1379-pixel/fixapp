// crates/backend-iphelper/src/routes.rs

use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;

use crate::sockaddr::{SOCKADDR_IN, SOCKADDR_IN6};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteProtocol {
    Other,
    Local,
    NetMgmt,
    Icmp,
    Egp,
    Ggp,
    Hello,
    Rip,
    IsIs,
    EsIs,
    CisCo,
    Ospf,
    Bgp,
    Unknown(u32),
}

impl RouteProtocol {
    pub fn from_u32(value: u32) -> Self {
        match value {
            1 => Self::Other,
            2 => Self::Local,
            3 => Self::NetMgmt,
            4 => Self::Icmp,
            5 => Self::Egp,
            6 => Self::Ggp,
            7 => Self::Hello,
            8 => Self::Rip,
            9 => Self::IsIs,
            10 => Self::EsIs,
            11 => Self::CisCo,
            12 => Self::Ospf,
            13 => Self::Bgp,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteType {
    Other,
    Invalid,
    Direct,
    Indirect,
}

impl RouteType {
    pub fn from_u32(value: u32) -> Self {
        match value {
            1 => Self::Other,
            2 => Self::Invalid,
            3 => Self::Direct,
            4 => Self::Indirect,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RouteInfo {
    pub destination: IpAddr,
    pub prefix_length: u8,
    pub next_hop: Option<IpAddr>,
    pub interface_index: u32,
    pub metric: u32,
    pub route_type: RouteType,
    pub protocol: RouteProtocol,
}

impl RouteInfo {
    pub fn new(
        destination: IpAddr,
        prefix_length: u8,
        next_hop: Option<IpAddr>,
        interface_index: u32,
        metric: u32,
    ) -> Option<Self> {
        let max_prefix = match destination {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        if prefix_length > max_prefix || interface_index == 0 {
            return None;
        }

        Some(Self {
            destination,
            prefix_length,
            next_hop,
            interface_index,
            metric,
            route_type: RouteType::Indirect,
            protocol: RouteProtocol::Unknown(0),
        })
    }

    pub fn matches(&self, address: IpAddr) -> bool {
        match (self.destination, address) {
            (IpAddr::V4(network), IpAddr::V4(target)) => {
                ipv4_matches(network, target, self.prefix_length)
            }
            (IpAddr::V6(network), IpAddr::V6(target)) => {
                ipv6_matches(network, target, self.prefix_length)
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteTableError {
    InvalidInterface,
    InvalidPrefix,
    RouteNotFound,
    SystemError(i32),
}

#[derive(Debug, Default)]
pub struct RouteTable {
    routes: Vec<RouteInfo>,
}

impl RouteTable {
    pub fn new() -> Self {
        Self { routes: Vec::new() }
    }

    pub fn insert(&mut self, route: RouteInfo) -> Result<(), RouteTableError> {
        if route.interface_index == 0 {
            return Err(RouteTableError::InvalidInterface);
        }

        let max_prefix = match route.destination {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if route.prefix_length > max_prefix {
            return Err(RouteTableError::InvalidPrefix);
        }

        if let Some(existing) = self.routes.iter_mut().find(|entry| {
            entry.destination == route.destination
                && entry.prefix_length == route.prefix_length
                && entry.interface_index == route.interface_index
        }) {
            *existing = route;
            return Ok(());
        }

        self.routes.push(route);
        Ok(())
    }

    pub fn lookup(&self, destination: IpAddr) -> Result<&RouteInfo, RouteTableError> {
        self.routes
            .iter()
            .filter(|route| route.matches(destination))
            .max_by(|a, b| {
                a.prefix_length
                    .cmp(&b.prefix_length)
                    .then_with(|| b.metric.cmp(&a.metric))
            })
            .ok_or(RouteTableError::RouteNotFound)
    }

    pub fn remove(
        &mut self,
        destination: IpAddr,
        prefix_length: u8,
        interface_index: u32,
    ) -> Result<RouteInfo, RouteTableError> {
        let position = self
            .routes
            .iter()
            .position(|route| {
                route.destination == destination
                    && route.prefix_length == prefix_length
                    && route.interface_index == interface_index
            })
            .ok_or(RouteTableError::RouteNotFound)?;

        Ok(self.routes.remove(position))
    }

    pub fn all(&self) -> &[RouteInfo] {
        &self.routes
    }

    pub fn clear(&mut self) {
        self.routes.clear();
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    #[cfg(windows)]
    pub fn refresh_all(&mut self) -> Result<(), RouteTableError> {
        self.clear();
        self.fetch_routes(sys::AF_INET)?;
        self.fetch_routes(sys::AF_INET6)?;
        Ok(())
    }

    #[cfg(windows)]
    fn fetch_routes(&mut self, family: u32) -> Result<(), RouteTableError> {
        let mut table_ptr: *mut sys::MIB_IPFORWARD_TABLE2 = ptr::null_mut();

        unsafe {
            let ret = sys::GetIpForwardTable2(family, &mut table_ptr);
            if ret != 0 {
                return Err(RouteTableError::SystemError(ret as i32));
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
                let destination = sys::parse_ip_prefix(&row.DestinationPrefix);
                let next_hop = sys::parse_sockaddr_inet(&row.NextHop);

                if let Some((dest_ip, prefix_len)) = destination {
                    if let Some(mut info) = RouteInfo::new(
                        dest_ip,
                        prefix_len,
                        next_hop,
                        row.InterfaceIndex,
                        row.Metric,
                    ) {
                        // `MIB_IPFORWARD_ROW2` does not expose a `RouteType`
                        // field. Only `Protocol` is available. Preserve the
                        // declared protocol and leave route_type as the
                        // default value set by `RouteInfo::new`.
                        info.protocol = RouteProtocol::from_u32(row.Protocol);
                        self.insert(info)?;
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
    const SOCKADDR_INET_LEN: usize = 28;

    #[repr(C)]
    pub struct MIB_IPPREFIX {
        pub Prefix: [u8; SOCKADDR_INET_LEN],
        pub PrefixLength: u8,
    }

    // Windows SDK MIB_IPFORWARD_ROW2 layout.
    // Note: this struct does NOT contain a RouteType field.
    #[repr(C)]
    pub struct MIB_IPFORWARD_ROW2 {
        pub InterfaceLuid: u64,
        pub InterfaceIndex: u32,
        pub DestinationPrefix: MIB_IPPREFIX,
        pub NextHop: [u8; SOCKADDR_INET_LEN],
        pub SitePrefixLength: u8,
        pub ValidLifetime: u32,
        pub PreferredLifetime: u32,
        pub Metric: u32,
        pub Protocol: u32,
        pub Loopback: bool,
        pub AutoconfigureAddress: bool,
        pub Publish: bool,
        pub Immortal: bool,
        pub Age: u32,
        pub Origin: u32,
    }

    #[repr(C)]
    pub struct MIB_IPFORWARD_TABLE2 {
        pub NumEntries: u32,
        pub Row: [MIB_IPFORWARD_ROW2; 1],
    }

    #[link(name = "iphlpapi")]
    extern "system" {
        pub fn GetIpForwardTable2(
            Family: u32,
            Table: *mut *mut MIB_IPFORWARD_TABLE2,
        ) -> u32;

        pub fn FreeMibTable(Memory: *mut c_void);
    }

    pub unsafe fn parse_ip_prefix(prefix: &MIB_IPPREFIX) -> Option<(IpAddr, u8)> {
        let ip = parse_sockaddr_inet(&prefix.Prefix)?;
        Some((ip, prefix.PrefixLength))
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

fn ipv4_matches(
    network: Ipv4Addr,
    target: Ipv4Addr,
    prefix_length: u8,
) -> bool {
    let network = u32::from(network);
    let target = u32::from(target);
    if prefix_length == 0 {
        return true;
    }
    let mask = u32::MAX << (32 - prefix_length);
    (network & mask) == (target & mask)
}

fn ipv6_matches(
    network: Ipv6Addr,
    target: Ipv6Addr,
    prefix_length: u8,
) -> bool {
    let network = u128::from_be_bytes(network.octets());
    let target = u128::from_be_bytes(target.octets());
    if prefix_length == 0 {
        return true;
    }
    let mask = u128::MAX << (128 - prefix_length);
    (network & mask) == (target & mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn creates_ipv4_route() {
        let route = RouteInfo::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
            24,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            1,
            10,
        );
        assert!(route.is_some());
    }

    #[test]
    fn invalid_prefix_is_rejected() {
        let route = RouteInfo::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
            33,
            None,
            1,
            10,
        );
        assert!(route.is_none());
    }

    #[test]
    fn route_matches_ipv4_destination() {
        let route = RouteInfo::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
            24,
            None,
            1,
            10,
        )
        .unwrap();

        assert!(route.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))));
        assert!(!route.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 50))));
    }

    #[test]
    fn route_matches_ipv6_destination() {
        let route = RouteInfo::new(
            IpAddr::V6("2001:db8::".parse::<Ipv6Addr>().unwrap()),
            32,
            None,
            1,
            10,
        )
        .unwrap();

        assert!(route.matches(IpAddr::V6("2001:db8:1::10".parse().unwrap())));
        assert!(!route.matches(IpAddr::V6("2001:dead::10".parse().unwrap())));
    }

    #[test]
    fn lookup_uses_longest_prefix() {
        let mut table = RouteTable::new();
        table
            .insert(
                RouteInfo::new(
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                    8,
                    None,
                    1,
                    1,
                )
                .unwrap(),
            )
            .unwrap();
        table
            .insert(
                RouteInfo::new(
                    IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)),
                    16,
                    None,
                    2,
                    100,
                )
                .unwrap(),
            )
            .unwrap();

        let route = table
            .lookup(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)))
            .unwrap();
        assert_eq!(route.interface_index, 2);
    }

    #[test]
    fn lookup_uses_lowest_metric_when_prefix_is_equal() {
        let mut table = RouteTable::new();
        table
            .insert(
                RouteInfo::new(
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                    8,
                    None,
                    1,
                    50,
                )
                .unwrap(),
            )
            .unwrap();
        table
            .insert(
                RouteInfo::new(
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                    8,
                    None,
                    2,
                    10,
                )
                .unwrap(),
            )
            .unwrap();

        let route = table
            .lookup(IpAddr::V4(Ipv4Addr::new(10, 5, 1, 2)))
            .unwrap();
        assert_eq!(route.interface_index, 2);
    }

    #[test]
    fn missing_route_returns_error() {
        let table = RouteTable::new();
        assert_eq!(
            table.lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            Err(RouteTableError::RouteNotFound)
        );
    }

    #[test]
    fn route_can_be_removed() {
        let mut table = RouteTable::new();
        let route = RouteInfo::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
            24,
            None,
            1,
            10,
        )
        .unwrap();
        table.insert(route).unwrap();

        let removed = table.remove(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
            24,
            1,
        );
        assert!(removed.is_ok());
        assert!(table.is_empty());
    }
}