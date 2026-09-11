// crates/backend-iphelper/src/connections.rs

use std::collections::HashSet;
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionProtocol {
    Tcp,
    Udp,
    Tcp6,
    Udp6,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
    Unknown,
}

impl ConnectionState {
    pub fn is_active(self) -> bool {
        matches!(
            self,
            Self::Listen
                | Self::SynSent
                | Self::SynReceived
                | Self::Established
                | Self::FinWait1
                | Self::FinWait2
                | Self::CloseWait
                | Self::Closing
                | Self::LastAck
                | Self::TimeWait
        )
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Closed | Self::DeleteTcb
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionKey {
    pub protocol: ConnectionProtocol,
    pub local_address: IpAddr,
    pub local_port: u16,
    pub remote_address: Option<IpAddr>,
    pub remote_port: Option<u16>,
}

impl ConnectionKey {
    pub fn new(
        protocol: ConnectionProtocol,
        local_address: IpAddr,
        local_port: u16,
        remote_address: Option<IpAddr>,
        remote_port: Option<u16>,
    ) -> Option<Self> {
        match (remote_address, remote_port) {
            (Some(_), None) | (None, Some(_)) => {
                return None;
            }
            _ => {}
        }

        Some(Self {
            protocol,
            local_address,
            local_port,
            remote_address,
            remote_port,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionInfo {
    pub key: ConnectionKey,
    pub state: ConnectionState,
    pub process_id: Option<u32>,
    pub owner_module: Option<String>,
    pub created_at: SystemTime,
    pub updated_at: SystemTime,
}

impl ConnectionInfo {
    pub fn new(
        key: ConnectionKey,
        state: ConnectionState,
    ) -> Self {
        let now = SystemTime::now();

        Self {
            key,
            state,
            process_id: None,
            owner_module: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn touch(&mut self) {
        self.updated_at = SystemTime::now();
    }

    pub fn age(&self) -> Duration {
        SystemTime::now()
            .duration_since(self.updated_at)
            .unwrap_or_default()
    }

    pub fn is_active(&self) -> bool {
        self.state.is_active()
    }

    pub fn set_process_id(
        &mut self,
        process_id: u32,
    ) {
        self.process_id = Some(process_id);
        self.touch();
    }

    pub fn set_owner_module(
        &mut self,
        module: impl Into<String>,
    ) {
        self.owner_module = Some(module.into());
        self.touch();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionTableError {
    InvalidPort,
    ConnectionNotFound,
    SystemError(i32),
}

#[derive(Debug, Default)]
pub struct ConnectionTable {
    connections: Vec<ConnectionInfo>,
}

impl ConnectionTable {
    pub fn new() -> Self {
        Self {
            connections: Vec::new(),
        }
    }

    pub fn insert(
        &mut self,
        connection: ConnectionInfo,
    ) -> Result<(), ConnectionTableError> {
        if connection.key.local_port == 0 {
            return Err(
                ConnectionTableError::InvalidPort
            );
        }

        if let Some(existing) =
            self.connections.iter_mut().find(|entry| {
                entry.key == connection.key
            })
        {
            let created = existing.created_at;
            *existing = connection;
            existing.created_at = created;
            return Ok(());
        }

        self.connections.push(connection);

        Ok(())
    }

    pub fn get(
        &self,
        key: &ConnectionKey,
    ) -> Result<&ConnectionInfo, ConnectionTableError> {
        self.connections
            .iter()
            .find(|entry| &entry.key == key)
            .ok_or(
                ConnectionTableError::ConnectionNotFound
            )
    }

    pub fn get_mut(
        &mut self,
        key: &ConnectionKey,
    ) -> Result<&mut ConnectionInfo, ConnectionTableError> {
        self.connections
            .iter_mut()
            .find(|entry| &entry.key == key)
            .ok_or(
                ConnectionTableError::ConnectionNotFound
            )
    }

    pub fn update_state(
        &mut self,
        key: &ConnectionKey,
        state: ConnectionState,
    ) -> Result<(), ConnectionTableError> {
        let connection = self.get_mut(key)?;

        connection.state = state;
        connection.touch();

        Ok(())
    }

    pub fn remove(
        &mut self,
        key: &ConnectionKey,
    ) -> Result<ConnectionInfo, ConnectionTableError> {
        let position = self
            .connections
            .iter()
            .position(|entry| &entry.key == key)
            .ok_or(
                ConnectionTableError::ConnectionNotFound
            )?;

        Ok(self.connections.remove(position))
    }

    pub fn remove_expired(
        &mut self,
        max_age: Duration,
    ) -> usize {
        let before = self.connections.len();

        self.connections.retain(|connection| {
            connection.age() <= max_age
        });

        before - self.connections.len()
    }

    pub fn active(
        &self,
    ) -> Vec<&ConnectionInfo> {
        self.connections
            .iter()
            .filter(|connection| {
                connection.is_active()
            })
            .collect()
    }

    pub fn all(&self) -> &[ConnectionInfo] {
        &self.connections
    }

    pub fn clear(&mut self) {
        self.connections.clear();
    }

    pub fn len(&self) -> usize {
        self.connections.len()
    }

    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    #[cfg(windows)]
    pub fn refresh_all(&mut self) -> Result<(), ConnectionTableError> {
        let mut current_keys = HashSet::new();

        self.fetch_tcp_v4(&mut current_keys)?;
        self.fetch_tcp_v6(&mut current_keys)?;
        self.fetch_udp_v4(&mut current_keys)?;
        self.fetch_udp_v6(&mut current_keys)?;

        self.connections.retain(|c| current_keys.contains(&c.key));

        Ok(())
    }

    #[cfg(windows)]
    fn fetch_tcp_v4(
        &mut self,
        current_keys: &mut HashSet<ConnectionKey>,
    ) -> Result<(), ConnectionTableError> {
        let mut size: u32 = 0;
        unsafe {
            let ret = sys::GetExtendedTcpTable(
                ptr::null_mut(),
                &mut size,
                false,
                sys::AF_INET,
                sys::TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            if ret != 0 && ret != sys::ERROR_INSUFFICIENT_BUFFER {
                return Err(ConnectionTableError::SystemError(ret as i32));
            }
        }

        let mut buffer: Vec<u8> = vec![0; size as usize];

        unsafe {
            let ret = sys::GetExtendedTcpTable(
                buffer.as_mut_ptr() as *mut c_void,
                &mut size,
                false,
                sys::AF_INET,
                sys::TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            if ret != 0 {
                return Err(ConnectionTableError::SystemError(ret as i32));
            }

            let table = &*(buffer.as_ptr() as *const sys::MIB_TCPTABLE_OWNER_PID);
            let entries = std::slice::from_raw_parts(
                &table.table as *const sys::MIB_TCPROW_OWNER_PID,
                table.dwNumEntries as usize,
            );

            for row in entries {
                let state = sys::map_tcp_state(row.dwState);
                let local_addr = IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr));
                let local_port = u16::from_be(row.dwLocalPort as u16);

                let remote_addr = if row.dwRemoteAddr != 0 {
                    Some(IpAddr::V4(Ipv4Addr::from(row.dwRemoteAddr)))
                } else {
                    None
                };

                let remote_port = if row.dwRemotePort != 0 {
                    Some(u16::from_be(row.dwRemotePort as u16))
                } else {
                    None
                };

                if let Some(key) = ConnectionKey::new(
                    ConnectionProtocol::Tcp,
                    local_addr,
                    local_port,
                    remote_addr,
                    remote_port,
                ) {
                    current_keys.insert(key.clone());

                    let mut info = ConnectionInfo::new(key, state);
                    info.set_process_id(row.dwOwningPid);

                    self.insert(info)?;
                }
            }
        }

        Ok(())
    }

    #[cfg(windows)]
    fn fetch_tcp_v6(
        &mut self,
        current_keys: &mut HashSet<ConnectionKey>,
    ) -> Result<(), ConnectionTableError> {
        let mut size: u32 = 0;
        unsafe {
            let ret = sys::GetExtendedTcpTable(
                ptr::null_mut(),
                &mut size,
                false,
                sys::AF_INET6,
                sys::TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            if ret != 0 && ret != sys::ERROR_INSUFFICIENT_BUFFER {
                return Err(ConnectionTableError::SystemError(ret as i32));
            }
        }

        let mut buffer: Vec<u8> = vec![0; size as usize];

        unsafe {
            let ret = sys::GetExtendedTcpTable(
                buffer.as_mut_ptr() as *mut c_void,
                &mut size,
                false,
                sys::AF_INET6,
                sys::TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            if ret != 0 {
                return Err(ConnectionTableError::SystemError(ret as i32));
            }

            let table = &*(buffer.as_ptr() as *const sys::MIB_TCP6TABLE_OWNER_PID);
            let entries = std::slice::from_raw_parts(
                &table.table as *const sys::MIB_TCP6ROW_OWNER_PID,
                table.dwNumEntries as usize,
            );

            for row in entries {
                let state = sys::map_tcp_state(row.dwState);
                let local_addr = IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr));
                let local_port = u16::from_be(row.dwLocalPort as u16);

                let remote_addr = if row.ucRemoteAddr != [0; 16] {
                    Some(IpAddr::V6(Ipv6Addr::from(row.ucRemoteAddr)))
                } else {
                    None
                };

                let remote_port = if row.dwRemotePort != 0 {
                    Some(u16::from_be(row.dwRemotePort as u16))
                } else {
                    None
                };

                if let Some(key) = ConnectionKey::new(
                    ConnectionProtocol::Tcp6,
                    local_addr,
                    local_port,
                    remote_addr,
                    remote_port,
                ) {
                    current_keys.insert(key.clone());

                    let mut info = ConnectionInfo::new(key, state);
                    info.set_process_id(row.dwOwningPid);

                    self.insert(info)?;
                }
            }
        }

        Ok(())
    }

    #[cfg(windows)]
    fn fetch_udp_v4(
        &mut self,
        current_keys: &mut HashSet<ConnectionKey>,
    ) -> Result<(), ConnectionTableError> {
        let mut size: u32 = 0;
        unsafe {
            let ret = sys::GetExtendedUdpTable(
                ptr::null_mut(),
                &mut size,
                false,
                sys::AF_INET,
                sys::UDP_TABLE_OWNER_PID_ALL,
                0,
            );

            if ret != 0 && ret != sys::ERROR_INSUFFICIENT_BUFFER {
                return Err(ConnectionTableError::SystemError(ret as i32));
            }
        }

        let mut buffer: Vec<u8> = vec![0; size as usize];

        unsafe {
            let ret = sys::GetExtendedUdpTable(
                buffer.as_mut_ptr() as *mut c_void,
                &mut size,
                false,
                sys::AF_INET,
                sys::UDP_TABLE_OWNER_PID_ALL,
                0,
            );

            if ret != 0 {
                return Err(ConnectionTableError::SystemError(ret as i32));
            }

            let table = &*(buffer.as_ptr() as *const sys::MIB_UDPTABLE_OWNER_PID);
            let entries = std::slice::from_raw_parts(
                &table.table as *const sys::MIB_UDPROW_OWNER_PID,
                table.dwNumEntries as usize,
            );

            for row in entries {
                let local_addr = IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr));
                let local_port = u16::from_be(row.dwLocalPort as u16);

                if let Some(key) = ConnectionKey::new(
                    ConnectionProtocol::Udp,
                    local_addr,
                    local_port,
                    None,
                    None,
                ) {
                    current_keys.insert(key.clone());

                    let mut info =
                        ConnectionInfo::new(key, ConnectionState::Established);
                    info.set_process_id(row.dwOwningPid);

                    self.insert(info)?;
                }
            }
        }

        Ok(())
    }

    #[cfg(windows)]
    fn fetch_udp_v6(
        &mut self,
        current_keys: &mut HashSet<ConnectionKey>,
    ) -> Result<(), ConnectionTableError> {
        let mut size: u32 = 0;
        unsafe {
            let ret = sys::GetExtendedUdpTable(
                ptr::null_mut(),
                &mut size,
                false,
                sys::AF_INET6,
                sys::UDP_TABLE_OWNER_PID_ALL,
                0,
            );

            if ret != 0 && ret != sys::ERROR_INSUFFICIENT_BUFFER {
                return Err(ConnectionTableError::SystemError(ret as i32));
            }
        }

        let mut buffer: Vec<u8> = vec![0; size as usize];

        unsafe {
            let ret = sys::GetExtendedUdpTable(
                buffer.as_mut_ptr() as *mut c_void,
                &mut size,
                false,
                sys::AF_INET6,
                sys::UDP_TABLE_OWNER_PID_ALL,
                0,
            );

            if ret != 0 {
                return Err(ConnectionTableError::SystemError(ret as i32));
            }

            let table = &*(buffer.as_ptr() as *const sys::MIB_UDP6TABLE_OWNER_PID);
            let entries = std::slice::from_raw_parts(
                &table.table as *const sys::MIB_UDP6ROW_OWNER_PID,
                table.dwNumEntries as usize,
            );

            for row in entries {
                let local_addr = IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr));
                let local_port = u16::from_be(row.dwLocalPort as u16);

                if let Some(key) = ConnectionKey::new(
                    ConnectionProtocol::Udp6,
                    local_addr,
                    local_port,
                    None,
                    None,
                ) {
                    current_keys.insert(key.clone());

                    let mut info =
                        ConnectionInfo::new(key, ConnectionState::Established);
                    info.set_process_id(row.dwOwningPid);

                    self.insert(info)?;
                }
            }
        }

        Ok(())
    }
}

#[cfg(windows)]
mod sys {
    use super::*;

    pub const AF_INET: u32 = 2;
    pub const AF_INET6: u32 = 23;
    pub const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

    pub const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
    pub const UDP_TABLE_OWNER_PID_ALL: u32 = 5;

    pub const MIB_TCP_STATE_CLOSED: u32 = 1;
    pub const MIB_TCP_STATE_LISTEN: u32 = 2;
    pub const MIB_TCP_STATE_SYN_SENT: u32 = 3;
    pub const MIB_TCP_STATE_SYN_RCVD: u32 = 4;
    pub const MIB_TCP_STATE_ESTAB: u32 = 5;
    pub const MIB_TCP_STATE_FIN_WAIT1: u32 = 6;
    pub const MIB_TCP_STATE_FIN_WAIT2: u32 = 7;
    pub const MIB_TCP_STATE_CLOSE_WAIT: u32 = 8;
    pub const MIB_TCP_STATE_CLOSING: u32 = 9;
    pub const MIB_TCP_STATE_LAST_ACK: u32 = 10;
    pub const MIB_TCP_STATE_TIME_WAIT: u32 = 11;
    pub const MIB_TCP_STATE_DELETE_TCB: u32 = 12;

    #[repr(C)]
    pub struct MIB_TCPROW_OWNER_PID {
        pub dwState: u32,
        pub dwLocalAddr: u32,
        pub dwLocalPort: u32,
        pub dwRemoteAddr: u32,
        pub dwRemotePort: u32,
        pub dwOwningPid: u32,
    }

    #[repr(C)]
    pub struct MIB_TCPTABLE_OWNER_PID {
        pub dwNumEntries: u32,
        pub table: [MIB_TCPROW_OWNER_PID; 1],
    }

    #[repr(C)]
    pub struct MIB_TCP6ROW_OWNER_PID {
        pub ucLocalAddr: [u8; 16],
        pub dwLocalScopeId: u32,
        pub dwLocalPort: u32,
        pub ucRemoteAddr: [u8; 16],
        pub dwRemoteScopeId: u32,
        pub dwRemotePort: u32,
        pub dwState: u32,
        pub dwOwningPid: u32,
    }

    #[repr(C)]
    pub struct MIB_TCP6TABLE_OWNER_PID {
        pub dwNumEntries: u32,
        pub table: [MIB_TCP6ROW_OWNER_PID; 1],
    }

    #[repr(C)]
    pub struct MIB_UDPROW_OWNER_PID {
        pub dwLocalAddr: u32,
        pub dwLocalPort: u32,
        pub dwOwningPid: u32,
    }

    #[repr(C)]
    pub struct MIB_UDPTABLE_OWNER_PID {
        pub dwNumEntries: u32,
        pub table: [MIB_UDPROW_OWNER_PID; 1],
    }

    #[repr(C)]
    pub struct MIB_UDP6ROW_OWNER_PID {
        pub ucLocalAddr: [u8; 16],
        pub dwLocalScopeId: u32,
        pub dwLocalPort: u32,
        pub dwOwningPid: u32,
    }

    #[repr(C)]
    pub struct MIB_UDP6TABLE_OWNER_PID {
        pub dwNumEntries: u32,
        pub table: [MIB_UDP6ROW_OWNER_PID; 1],
    }

    #[link(name = "iphlpapi")]
    extern "system" {
        pub fn GetExtendedTcpTable(
            pTcpTable: *mut c_void,
            pdwSize: *mut u32,
            bOrder: bool,
            ulAf: u32,
            tcpTableClass: u32,
            reserved: u32,
        ) -> u32;

        pub fn GetExtendedUdpTable(
            pUdpTable: *mut c_void,
            pdwSize: *mut u32,
            bOrder: bool,
            ulAf: u32,
            udpTableClass: u32,
            reserved: u32,
        ) -> u32;
    }

    pub fn map_tcp_state(state: u32) -> ConnectionState {
        match state {
            MIB_TCP_STATE_CLOSED => ConnectionState::Closed,
            MIB_TCP_STATE_LISTEN => ConnectionState::Listen,
            MIB_TCP_STATE_SYN_SENT => ConnectionState::SynSent,
            MIB_TCP_STATE_SYN_RCVD => ConnectionState::SynReceived,
            MIB_TCP_STATE_ESTAB => ConnectionState::Established,
            MIB_TCP_STATE_FIN_WAIT1 => ConnectionState::FinWait1,
            MIB_TCP_STATE_FIN_WAIT2 => ConnectionState::FinWait2,
            MIB_TCP_STATE_CLOSE_WAIT => ConnectionState::CloseWait,
            MIB_TCP_STATE_CLOSING => ConnectionState::Closing,
            MIB_TCP_STATE_LAST_ACK => ConnectionState::LastAck,
            MIB_TCP_STATE_TIME_WAIT => ConnectionState::TimeWait,
            MIB_TCP_STATE_DELETE_TCB => ConnectionState::DeleteTcb,
            _ => ConnectionState::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn local_address() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))
    }

    fn remote_address() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
    }

    fn connection_key() -> ConnectionKey {
        ConnectionKey::new(
            ConnectionProtocol::Tcp,
            local_address(),
            50000,
            Some(remote_address()),
            Some(443),
        )
        .unwrap()
    }

    #[test]
    fn creates_connection_key() {
        let key = connection_key();
        assert_eq!(key.local_port, 50000);
        assert_eq!(key.remote_port, Some(443));
    }

    #[test]
    fn mismatched_remote_endpoint_is_rejected() {
        let key = ConnectionKey::new(
            ConnectionProtocol::Tcp,
            local_address(),
            50000,
            Some(remote_address()),
            None,
        );
        assert!(key.is_none());
    }

    #[test]
    fn inserts_and_gets_connection() {
        let mut table = ConnectionTable::new();
        let key = connection_key();

        table
            .insert(ConnectionInfo::new(
                key.clone(),
                ConnectionState::Established,
            ))
            .unwrap();

        let connection = table.get(&key).unwrap();
        assert_eq!(connection.state, ConnectionState::Established);
    }

    #[test]
    fn updates_connection_state() {
        let mut table = ConnectionTable::new();
        let key = connection_key();

        table
            .insert(ConnectionInfo::new(
                key.clone(),
                ConnectionState::SynSent,
            ))
            .unwrap();

        table
            .update_state(&key, ConnectionState::Established)
            .unwrap();

        assert_eq!(
            table.get(&key).unwrap().state,
            ConnectionState::Established
        );
    }

    #[test]
    fn active_connections_are_filtered() {
        let mut table = ConnectionTable::new();

        let key1 = connection_key();
        let key2 = ConnectionKey::new(
            ConnectionProtocol::Tcp,
            local_address(),
            50001,
            Some(remote_address()),
            Some(80),
        )
        .unwrap();

        table
            .insert(ConnectionInfo::new(
                key1,
                ConnectionState::Established,
            ))
            .unwrap();

        table
            .insert(ConnectionInfo::new(
                key2,
                ConnectionState::Closed,
            ))
            .unwrap();

        assert_eq!(table.active().len(), 1);
    }

    #[test]
    fn process_information_can_be_attached() {
        let key = connection_key();

        let mut connection =
            ConnectionInfo::new(key, ConnectionState::Established);

        connection.set_process_id(1234);
        connection.set_owner_module("example.exe");

        assert_eq!(connection.process_id, Some(1234));
        assert_eq!(
            connection.owner_module.as_deref(),
            Some("example.exe")
        );
    }

    #[test]
    fn invalid_local_port_is_rejected() {
        let key = ConnectionKey::new(
            ConnectionProtocol::Tcp,
            local_address(),
            0,
            None,
            None,
        )
        .unwrap();

        let mut table = ConnectionTable::new();

        let result = table.insert(ConnectionInfo::new(
            key,
            ConnectionState::Listen,
        ));

        assert_eq!(
            result,
            Err(ConnectionTableError::InvalidPort)
        );
    }

    #[test]
    fn removes_connection() {
        let mut table = ConnectionTable::new();
        let key = connection_key();

        table
            .insert(ConnectionInfo::new(
                key.clone(),
                ConnectionState::Established,
            ))
            .unwrap();

        let removed = table.remove(&key);
        assert!(removed.is_ok());
        assert!(table.is_empty());
    }

    #[test]
    fn missing_connection_returns_error() {
        let table = ConnectionTable::new();
        let key = connection_key();

        assert_eq!(
            table.get(&key).unwrap_err(),
            ConnectionTableError::ConnectionNotFound
        );
    }
}