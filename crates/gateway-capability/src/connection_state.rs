use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionProtocol {
    Tcp,
    Udp,
    Icmp,
    IcmpV6,
    Other(u8),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionKey {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub protocol: ConnectionProtocol,
}

impl ConnectionKey {
    pub fn new(
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        protocol: ConnectionProtocol,
    ) -> Self {
        Self {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol,
        }
    }

    pub fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            src_port: self.dst_port,
            dst_ip: self.src_ip,
            dst_port: self.src_port,
            protocol: self.protocol,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    New,
    Established,
    Closing,
    Closed,
    Failed,
}

impl ConnectionState {
    pub fn can_transition_to(
        self,
        next: ConnectionState,
    ) -> bool {
        use ConnectionState::*;

        matches!(
            (self, next),
            (New, New)
                | (New, Established)
                | (New, Failed)
                | (Established, Established)
                | (Established, Closing)
                | (Established, Failed)
                | (Closing, Closing)
                | (Closing, Closed)
                | (Closing, Failed)
                | (Failed, Failed)
                | (Closed, Closed)
        )
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            ConnectionState::Closed
                | ConnectionState::Failed
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStateError {
    InvalidTransition {
        from: ConnectionState,
        to: ConnectionState,
    },
    CapacityExceeded,
    AlreadyExists,
    NotFound,
    InvalidTimeout,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConnectionEntry {
    pub key: ConnectionKey,
    pub state: ConnectionState,
    pub created_at: u64,
    pub last_seen: u64,
    pub timeout_secs: u64,
    pub packets_forwarded: u64,
    pub bytes_forwarded: u64,
}

impl ConnectionEntry {
    pub fn new(
        key: ConnectionKey,
        timeout_secs: u64,
    ) -> Result<Self, ConnectionStateError> {
        if timeout_secs == 0 {
            return Err(
                ConnectionStateError::InvalidTimeout
            );
        }

        let now = unix_seconds();

        Ok(Self {
            key,
            state: ConnectionState::New,
            created_at: now,
            last_seen: now,
            timeout_secs,
            packets_forwarded: 0,
            bytes_forwarded: 0,
        })
    }

    pub fn is_expired(&self, now: u64) -> bool {
        now.saturating_sub(self.last_seen)
            >= self.timeout_secs
    }

    pub fn touch(&mut self) {
        self.last_seen = unix_seconds();
    }

    pub fn record_packet(&mut self, bytes: usize) {
        self.packets_forwarded =
            self.packets_forwarded.saturating_add(1);

        self.bytes_forwarded =
            self.bytes_forwarded
                .saturating_add(bytes as u64);

        self.touch();
    }

    pub fn transition(
        &mut self,
        next: ConnectionState,
    ) -> Result<(), ConnectionStateError> {
        if self.state == next {
            return Ok(());
        }

        if !self.state.can_transition_to(next) {
            return Err(
                ConnectionStateError::InvalidTransition {
                    from: self.state,
                    to: next,
                },
            );
        }

        self.state = next;
        self.touch();

        Ok(())
    }
}

#[derive(Debug)]
pub struct ConnectionStateTable {
    entries: HashMap<ConnectionKey, ConnectionEntry>,
    max_entries: usize,
}

impl ConnectionStateTable {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(max_entries),
            max_entries,
        }
    }

    pub fn insert(
        &mut self,
        entry: ConnectionEntry,
    ) -> Result<(), ConnectionStateError> {
        self.remove_expired();

        if self.entries.contains_key(&entry.key) {
            return Err(
                ConnectionStateError::AlreadyExists
            );
        }

        if self.entries.len() >= self.max_entries {
            return Err(
                ConnectionStateError::CapacityExceeded
            );
        }

        self.entries.insert(entry.key.clone(), entry);

        Ok(())
    }

    pub fn get(
        &self,
        key: &ConnectionKey,
    ) -> Option<&ConnectionEntry> {
        self.entries.get(key)
    }

    pub fn get_mut(
        &mut self,
        key: &ConnectionKey,
    ) -> Option<&mut ConnectionEntry> {
        self.entries.get_mut(key)
    }

    pub fn lookup(
        &self,
        key: &ConnectionKey,
    ) -> Option<&ConnectionEntry> {
        let entry = self.entries.get(key)?;
        let now = unix_seconds();

        if entry.is_expired(now) {
            return None;
        }

        Some(entry)
    }

    pub fn lookup_reverse(
        &self,
        key: &ConnectionKey,
    ) -> Option<&ConnectionEntry> {
        self.lookup(&key.reverse())
    }

    pub fn transition(
        &mut self,
        key: &ConnectionKey,
        next: ConnectionState,
    ) -> Result<(), ConnectionStateError> {
        let entry = self
            .get_mut(key)
            .ok_or(ConnectionStateError::NotFound)?;

        entry.transition(next)
    }

    pub fn record_packet(
        &mut self,
        key: &ConnectionKey,
        bytes: usize,
    ) -> Result<(), ConnectionStateError> {
        let entry = self
            .get_mut(key)
            .ok_or(ConnectionStateError::NotFound)?;

        entry.record_packet(bytes);

        Ok(())
    }

    pub fn remove(
        &mut self,
        key: &ConnectionKey,
    ) -> Option<ConnectionEntry> {
        self.entries.remove(key)
    }

    pub fn remove_expired(&mut self) -> usize {
        let now = unix_seconds();

        let expired: Vec<ConnectionKey> = self
            .entries
            .iter()
            .filter_map(|(key, entry)| {
                if entry.is_expired(now) {
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect();

        let count = expired.len();

        for key in expired {
            self.entries.remove(&key);
        }

        count
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    pub fn entries(
        &self,
    ) -> impl Iterator<Item = &ConnectionEntry> {
        self.entries.values()
    }
}

impl Default for ConnectionStateTable {
    fn default() -> Self {
        Self::new(65_536)
    }
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn key() -> ConnectionKey {
        ConnectionKey::new(
            ip(192, 168, 1, 10),
            50_000,
            ip(8, 8, 8, 8),
            443,
            ConnectionProtocol::Tcp,
        )
    }

    #[test]
    fn create_connection() {
        let entry =
            ConnectionEntry::new(key(), 60).unwrap();

        assert_eq!(
            entry.state,
            ConnectionState::New
        );
        assert_eq!(entry.packets_forwarded, 0);
        assert_eq!(entry.bytes_forwarded, 0);
    }

    #[test]
    fn insert_and_lookup() {
        let mut table =
            ConnectionStateTable::new(100);

        let connection_key = key();

        table
            .insert(
                ConnectionEntry::new(
                    connection_key.clone(),
                    60,
                )
                .unwrap(),
            )
            .unwrap();

        let entry =
            table.lookup(&connection_key).unwrap();

        assert_eq!(
            entry.state,
            ConnectionState::New
        );
    }

    #[test]
    fn reverse_lookup_works() {
        let mut table =
            ConnectionStateTable::new(100);

        let original = key();
        let reverse = original.reverse();

        table
            .insert(
                ConnectionEntry::new(
                    original.clone(),
                    60,
                )
                .unwrap(),
            )
            .unwrap();

        assert!(
            table.lookup_reverse(&reverse).is_some()
        );
    }

    #[test]
    fn valid_state_transition() {
        let mut table =
            ConnectionStateTable::new(100);

        let connection_key = key();

        table
            .insert(
                ConnectionEntry::new(
                    connection_key.clone(),
                    60,
                )
                .unwrap(),
            )
            .unwrap();

        table
            .transition(
                &connection_key,
                ConnectionState::Established,
            )
            .unwrap();

        assert_eq!(
            table
                .get(&connection_key)
                .unwrap()
                .state,
            ConnectionState::Established
        );
    }

    #[test]
    fn invalid_state_transition_is_rejected() {
        let mut table =
            ConnectionStateTable::new(100);

        let connection_key = key();

        table
            .insert(
                ConnectionEntry::new(
                    connection_key.clone(),
                    60,
                )
                .unwrap(),
            )
            .unwrap();

        let result = table.transition(
            &connection_key,
            ConnectionState::Closed,
        );

        assert!(matches!(
            result,
            Err(
                ConnectionStateError::InvalidTransition {
                    from: ConnectionState::New,
                    to: ConnectionState::Closed
                }
            )
        ));
    }

    #[test]
    fn record_packet_updates_counters() {
        let mut table =
            ConnectionStateTable::new(100);

        let connection_key = key();

        table
            .insert(
                ConnectionEntry::new(
                    connection_key.clone(),
                    60,
                )
                .unwrap(),
            )
            .unwrap();

        table
            .record_packet(&connection_key, 1500)
            .unwrap();

        table
            .record_packet(&connection_key, 500)
            .unwrap();

        let entry =
            table.get(&connection_key).unwrap();

        assert_eq!(entry.packets_forwarded, 2);
        assert_eq!(entry.bytes_forwarded, 2000);
    }

    #[test]
    fn duplicate_connection_is_rejected() {
        let mut table =
            ConnectionStateTable::new(100);

        let connection_key = key();

        let entry =
            ConnectionEntry::new(
                connection_key.clone(),
                60,
            )
            .unwrap();

        table.insert(entry.clone()).unwrap();

        assert_eq!(
            table.insert(entry),
            Err(
                ConnectionStateError::AlreadyExists
            )
        );
    }

    #[test]
    fn capacity_is_enforced() {
        let mut table =
            ConnectionStateTable::new(1);

        table
            .insert(
                ConnectionEntry::new(key(), 60)
                    .unwrap(),
            )
            .unwrap();

        let second_key =
            ConnectionKey::new(
                ip(192, 168, 1, 20),
                50_001,
                ip(8, 8, 8, 8),
                443,
                ConnectionProtocol::Tcp,
            );

        let result = table.insert(
            ConnectionEntry::new(
                second_key,
                60,
            )
            .unwrap(),
        );

        assert_eq!(
            result,
            Err(
                ConnectionStateError::CapacityExceeded
            )
        );
    }

    #[test]
    fn protocol_is_part_of_connection_identity() {
        let mut table =
            ConnectionStateTable::new(100);

        let tcp = key();

        let udp = ConnectionKey::new(
            tcp.src_ip,
            tcp.src_port,
            tcp.dst_ip,
            tcp.dst_port,
            ConnectionProtocol::Udp,
        );

        table
            .insert(
                ConnectionEntry::new(
                    tcp,
                    60,
                )
                .unwrap(),
            )
            .unwrap();

        table
            .insert(
                ConnectionEntry::new(
                    udp,
                    60,
                )
                .unwrap(),
            )
            .unwrap();

        assert_eq!(table.len(), 2);
    }

    #[test]
    fn remove_connection() {
        let mut table =
            ConnectionStateTable::new(100);

        let connection_key = key();

        table
            .insert(
                ConnectionEntry::new(
                    connection_key.clone(),
                    60,
                )
                .unwrap(),
            )
            .unwrap();

        assert!(
            table.remove(&connection_key).is_some()
        );

        assert!(
            table.lookup(&connection_key).is_none()
        );
    }

    #[test]
    fn zero_timeout_is_rejected() {
        let result =
            ConnectionEntry::new(key(), 0);

        assert_eq!(
            result,
            Err(
                ConnectionStateError::InvalidTimeout
            )
        );
    }

    #[test]
    fn terminal_states_are_detected() {
        assert!(
            ConnectionState::Closed.is_terminal()
        );

        assert!(
            ConnectionState::Failed.is_terminal()
        );

        assert!(
            !ConnectionState::Established.is_terminal()
        );
    }
}