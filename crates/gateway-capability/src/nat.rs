use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NatProtocol {
    Tcp,
    Udp,
    Icmp,
    IcmpV6,
    Other(u8),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NatTuple {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub protocol: NatProtocol,
}

impl NatTuple {
    pub fn new(
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        protocol: NatProtocol,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatEntry {
    pub id: u64,
    pub original: NatTuple,
    pub translated: NatTuple,
    pub created_at: u64,
    pub last_seen: u64,
    pub timeout_secs: u64,
    pub enabled: bool,
}

impl NatEntry {
    pub fn new(
        id: u64,
        original: NatTuple,
        translated: NatTuple,
        timeout_secs: u64,
    ) -> Self {
        let now = unix_seconds();

        Self {
            id,
            original,
            translated,
            created_at: now,
            last_seen: now,
            timeout_secs,
            enabled: true,
        }
    }

    pub fn is_expired(&self, now: u64) -> bool {
        now.saturating_sub(self.last_seen) >= self.timeout_secs
    }

    pub fn touch(&mut self, now: u64) {
        self.last_seen = now;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatError {
    CapacityExceeded,
    DuplicateMapping,
    MappingNotFound,
    InvalidTimeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatLookupDirection {
    Original,
    Translated,
}

#[derive(Debug)]
pub struct NatTable {
    entries: HashMap<u64, NatEntry>,
    original_index: HashMap<NatTuple, u64>,
    translated_index: HashMap<NatTuple, u64>,
    max_entries: usize,
    next_id: u64,
}

impl NatTable {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(max_entries),
            original_index: HashMap::with_capacity(max_entries),
            translated_index: HashMap::with_capacity(max_entries),
            max_entries,
            next_id: 1,
        }
    }

    pub fn insert(
        &mut self,
        original: NatTuple,
        translated: NatTuple,
        timeout_secs: u64,
    ) -> Result<u64, NatError> {
        if timeout_secs == 0 {
            return Err(NatError::InvalidTimeout);
        }

        self.remove_expired();

        if self.entries.len() >= self.max_entries {
            return Err(NatError::CapacityExceeded);
        }

        if self.original_index.contains_key(&original)
            || self.translated_index.contains_key(&translated)
        {
            return Err(NatError::DuplicateMapping);
        }

        let id = self.allocate_id();

        let entry = NatEntry::new(
            id,
            original.clone(),
            translated.clone(),
            timeout_secs,
        );

        self.entries.insert(id, entry);
        self.original_index.insert(original, id);
        self.translated_index.insert(translated, id);

        Ok(id)
    }

    pub fn get(&self, id: u64) -> Option<&NatEntry> {
        self.entries.get(&id)
    }

    pub fn get_mut(&mut self, id: u64) -> Option<&mut NatEntry> {
        self.entries.get_mut(&id)
    }

    pub fn lookup_original(
        &self,
        tuple: &NatTuple,
    ) -> Option<&NatEntry> {
        let id = self.original_index.get(tuple)?;
        self.entries.get(id)
    }

    pub fn lookup_translated(
        &self,
        tuple: &NatTuple,
    ) -> Option<&NatEntry> {
        let id = self.translated_index.get(tuple)?;
        self.entries.get(id)
    }

    pub fn lookup(
        &self,
        tuple: &NatTuple,
        direction: NatLookupDirection,
    ) -> Option<&NatEntry> {
        match direction {
            NatLookupDirection::Original => {
                self.lookup_original(tuple)
            }
            NatLookupDirection::Translated => {
                self.lookup_translated(tuple)
            }
        }
    }

    pub fn touch(&mut self, id: u64) -> bool {
        let now = unix_seconds();

        if let Some(entry) = self.entries.get_mut(&id) {
            entry.touch(now);
            true
        } else {
            false
        }
    }

    pub fn remove(&mut self, id: u64) -> Option<NatEntry> {
        let entry = self.entries.remove(&id)?;

        self.original_index.remove(&entry.original);
        self.translated_index.remove(&entry.translated);

        Some(entry)
    }

    pub fn remove_expired(&mut self) -> usize {
        let now = unix_seconds();

        let expired: Vec<u64> = self
            .entries
            .iter()
            .filter_map(|(id, entry)| {
                if entry.is_expired(now) {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect();

        let count = expired.len();

        for id in expired {
            self.remove(id);
        }

        count
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.original_index.clear();
        self.translated_index.clear();
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

    pub fn iter(&self) -> impl Iterator<Item = &NatEntry> {
        self.entries.values()
    }

    fn allocate_id(&mut self) -> u64 {
        let id = self.next_id;

        self.next_id = self.next_id.wrapping_add(1);

        if self.next_id == 0 {
            self.next_id = 1;
        }

        id
    }
}

impl Default for NatTable {
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

    fn original_tuple() -> NatTuple {
        NatTuple::new(
            ip(192, 168, 1, 10),
            50_000,
            ip(8, 8, 8, 8),
            443,
            NatProtocol::Tcp,
        )
    }

    fn translated_tuple() -> NatTuple {
        NatTuple::new(
            ip(203, 0, 113, 10),
            40_000,
            ip(8, 8, 8, 8),
            443,
            NatProtocol::Tcp,
        )
    }

    #[test]
    fn insert_and_lookup_original() {
        let mut table = NatTable::new(100);

        let original = original_tuple();
        let translated = translated_tuple();

        let id = table
            .insert(
                original.clone(),
                translated,
                60,
            )
            .unwrap();

        let entry = table
            .lookup_original(&original)
            .unwrap();

        assert_eq!(entry.id, id);
        assert_eq!(entry.original, original);
    }

    #[test]
    fn lookup_translated() {
        let mut table = NatTable::new(100);

        let original = original_tuple();
        let translated = translated_tuple();

        table
            .insert(
                original,
                translated.clone(),
                60,
            )
            .unwrap();

        let entry = table
            .lookup_translated(&translated)
            .unwrap();

        assert_eq!(entry.translated, translated);
    }

    #[test]
    fn duplicate_original_is_rejected() {
        let mut table = NatTable::new(100);

        let original = original_tuple();

        table
            .insert(
                original.clone(),
                translated_tuple(),
                60,
            )
            .unwrap();

        let result = table.insert(
            original,
            NatTuple::new(
                ip(203, 0, 113, 20),
                40_001,
                ip(1, 1, 1, 1),
                443,
                NatProtocol::Tcp,
            ),
            60,
        );

        assert_eq!(
            result,
            Err(NatError::DuplicateMapping)
        );
    }

    #[test]
    fn duplicate_translated_is_rejected() {
        let mut table = NatTable::new(100);

        let translated = translated_tuple();

        table
            .insert(
                original_tuple(),
                translated.clone(),
                60,
            )
            .unwrap();

        let result = table.insert(
            NatTuple::new(
                ip(192, 168, 1, 20),
                50_001,
                ip(8, 8, 4, 4),
                443,
                NatProtocol::Tcp,
            ),
            translated,
            60,
        );

        assert_eq!(
            result,
            Err(NatError::DuplicateMapping)
        );
    }

    #[test]
    fn capacity_is_enforced() {
        let mut table = NatTable::new(1);

        table
            .insert(
                original_tuple(),
                translated_tuple(),
                60,
            )
            .unwrap();

        let result = table.insert(
            NatTuple::new(
                ip(192, 168, 1, 20),
                50_001,
                ip(8, 8, 8, 8),
                443,
                NatProtocol::Tcp,
            ),
            NatTuple::new(
                ip(203, 0, 113, 20),
                40_001,
                ip(8, 8, 8, 8),
                443,
                NatProtocol::Tcp,
            ),
            60,
        );

        assert_eq!(
            result,
            Err(NatError::CapacityExceeded)
        );
    }

    #[test]
    fn zero_timeout_is_rejected() {
        let mut table = NatTable::new(100);

        let result = table.insert(
            original_tuple(),
            translated_tuple(),
            0,
        );

        assert_eq!(
            result,
            Err(NatError::InvalidTimeout)
        );
    }

    #[test]
    fn remove_mapping_cleans_indexes() {
        let mut table = NatTable::new(100);

        let original = original_tuple();
        let translated = translated_tuple();

        let id = table
            .insert(
                original.clone(),
                translated.clone(),
                60,
            )
            .unwrap();

        assert!(table.remove(id).is_some());

        assert!(
            table.lookup_original(&original).is_none()
        );

        assert!(
            table.lookup_translated(&translated).is_none()
        );

        assert_eq!(table.len(), 0);
    }

    #[test]
    fn touch_updates_existing_entry() {
        let mut table = NatTable::new(100);

        let id = table
            .insert(
                original_tuple(),
                translated_tuple(),
                60,
            )
            .unwrap();

        assert!(table.touch(id));
        assert!(table.get(id).is_some());
    }

    #[test]
    fn missing_mapping_returns_none() {
        let table = NatTable::new(100);

        assert!(
            table
                .lookup_original(&original_tuple())
                .is_none()
        );
    }

    #[test]
    fn reverse_tuple_swaps_endpoints() {
        let tuple = original_tuple();
        let reversed = tuple.reverse();

        assert_eq!(reversed.src_ip, tuple.dst_ip);
        assert_eq!(reversed.dst_ip, tuple.src_ip);
        assert_eq!(reversed.src_port, tuple.dst_port);
        assert_eq!(reversed.dst_port, tuple.src_port);
        assert_eq!(reversed.protocol, tuple.protocol);
    }

    #[test]
    fn tcp_and_udp_are_distinct() {
        let mut table = NatTable::new(100);

        let tcp = original_tuple();

        let udp = NatTuple::new(
            tcp.src_ip,
            tcp.src_port,
            tcp.dst_ip,
            tcp.dst_port,
            NatProtocol::Udp,
        );

        assert!(
            table
                .insert(
                    tcp,
                    translated_tuple(),
                    60
                )
                .is_ok()
        );

        assert!(
            table
                .insert(
                    udp,
                    NatTuple::new(
                        ip(203, 0, 113, 11),
                        40_001,
                        ip(8, 8, 8, 8),
                        443,
                        NatProtocol::Udp,
                    ),
                    60
                )
                .is_ok()
        );

        assert_eq!(table.len(), 2);
    }
}