use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeighborState {
    Reachable,
    Stale,
    Delay,
    Probe,
    Failed,
}

impl NeighborState {
    pub fn is_usable(self) -> bool {
        matches!(
            self,
            NeighborState::Reachable
                | NeighborState::Stale
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NeighborKey {
    pub address: IpAddr,
    pub interface_id: u32,
}

impl NeighborKey {
    pub fn new(address: IpAddr, interface_id: u32) -> Self {
        Self {
            address,
            interface_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighborEntry {
    pub key: NeighborKey,
    pub link_layer_address: Option<[u8; 6]>,
    pub state: NeighborState,
    pub created_at: u64,
    pub last_updated: u64,
    pub expires_at: Option<u64>,
}

impl NeighborEntry {
    pub fn new(
        address: IpAddr,
        interface_id: u32,
        link_layer_address: Option<[u8; 6]>,
        state: NeighborState,
        ttl_secs: Option<u64>,
    ) -> Self {
        let now = unix_seconds();

        let expires_at = ttl_secs.map(|ttl| now.saturating_add(ttl));

        Self {
            key: NeighborKey::new(address, interface_id),
            link_layer_address,
            state,
            created_at: now,
            last_updated: now,
            expires_at,
        }
    }

    pub fn is_expired(&self, now: u64) -> bool {
        match self.expires_at {
            Some(expires_at) => now >= expires_at,
            None => false,
        }
    }

    pub fn is_usable(&self, now: u64) -> bool {
        !self.is_expired(now) && self.state.is_usable()
    }

    pub fn touch(&mut self) {
        self.last_updated = unix_seconds();
    }

    pub fn set_state(&mut self, state: NeighborState) {
        self.state = state;
        self.last_updated = unix_seconds();
    }

    pub fn set_link_layer_address(
        &mut self,
        address: Option<[u8; 6]>,
    ) {
        self.link_layer_address = address;
        self.last_updated = unix_seconds();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeighborError {
    CapacityExceeded,
    InvalidInterface,
    AlreadyExists,
    NotFound,
}

#[derive(Debug)]
pub struct NeighborCache {
    entries: HashMap<NeighborKey, NeighborEntry>,
    max_entries: usize,
}

impl NeighborCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(max_entries),
            max_entries,
        }
    }

    pub fn insert(
        &mut self,
        entry: NeighborEntry,
    ) -> Result<(), NeighborError> {
        if entry.key.interface_id == 0 {
            return Err(NeighborError::InvalidInterface);
        }

        self.remove_expired();

        if self.entries.contains_key(&entry.key) {
            return Err(NeighborError::AlreadyExists);
        }

        if self.entries.len() >= self.max_entries {
            return Err(NeighborError::CapacityExceeded);
        }

        self.entries.insert(entry.key.clone(), entry);

        Ok(())
    }

    pub fn upsert(
        &mut self,
        entry: NeighborEntry,
    ) -> Result<(), NeighborError> {
        if entry.key.interface_id == 0 {
            return Err(NeighborError::InvalidInterface);
        }

        self.remove_expired();

        if self.entries.contains_key(&entry.key) {
            self.entries.insert(entry.key.clone(), entry);
            return Ok(());
        }

        if self.entries.len() >= self.max_entries {
            return Err(NeighborError::CapacityExceeded);
        }

        self.entries.insert(entry.key.clone(), entry);

        Ok(())
    }

    pub fn get(
        &self,
        address: IpAddr,
        interface_id: u32,
    ) -> Option<&NeighborEntry> {
        self.entries.get(&NeighborKey::new(
            address,
            interface_id,
        ))
    }

    pub fn get_mut(
        &mut self,
        address: IpAddr,
        interface_id: u32,
    ) -> Option<&mut NeighborEntry> {
        self.entries.get_mut(&NeighborKey::new(
            address,
            interface_id,
        ))
    }

    pub fn lookup(
        &self,
        address: IpAddr,
        interface_id: u32,
    ) -> Option<&NeighborEntry> {
        let entry = self.get(address, interface_id)?;
        let now = unix_seconds();

        if entry.is_usable(now) {
            Some(entry)
        } else {
            None
        }
    }

    pub fn resolve(
        &self,
        address: IpAddr,
        interface_id: u32,
    ) -> Result<[u8; 6], NeighborError> {
        let entry = self
            .lookup(address, interface_id)
            .ok_or(NeighborError::NotFound)?;

        entry
            .link_layer_address
            .ok_or(NeighborError::NotFound)
    }

    pub fn set_state(
        &mut self,
        address: IpAddr,
        interface_id: u32,
        state: NeighborState,
    ) -> Result<(), NeighborError> {
        let entry = self
            .get_mut(address, interface_id)
            .ok_or(NeighborError::NotFound)?;

        entry.set_state(state);

        Ok(())
    }

    pub fn remove(
        &mut self,
        address: IpAddr,
        interface_id: u32,
    ) -> Option<NeighborEntry> {
        self.entries.remove(&NeighborKey::new(
            address,
            interface_id,
        ))
    }

    pub fn remove_expired(&mut self) -> usize {
        let now = unix_seconds();

        let expired: Vec<NeighborKey> = self
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

    pub fn entries(&self) -> impl Iterator<Item = &NeighborEntry> {
        self.entries.values()
    }
}

impl Default for NeighborCache {
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

    fn mac() -> [u8; 6] {
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
    }

    fn entry() -> NeighborEntry {
        NeighborEntry::new(
            ip(192, 168, 1, 1),
            1,
            Some(mac()),
            NeighborState::Reachable,
            Some(60),
        )
    }

    #[test]
    fn insert_and_get() {
        let mut cache = NeighborCache::new(100);

        cache.insert(entry()).unwrap();

        let result = cache
            .get(ip(192, 168, 1, 1), 1)
            .unwrap();

        assert_eq!(
            result.state,
            NeighborState::Reachable
        );
        assert_eq!(
            result.link_layer_address,
            Some(mac())
        );
    }

    #[test]
    fn lookup_requires_usable_state() {
        let mut cache = NeighborCache::new(100);

        let mut neighbor = entry();
        neighbor.state = NeighborState::Failed;

        cache.insert(neighbor).unwrap();

        assert!(
            cache
                .lookup(ip(192, 168, 1, 1), 1)
                .is_none()
        );
    }

    #[test]
    fn resolve_returns_mac() {
        let mut cache = NeighborCache::new(100);

        cache.insert(entry()).unwrap();

        let result = cache
            .resolve(ip(192, 168, 1, 1), 1)
            .unwrap();

        assert_eq!(result, mac());
    }

    #[test]
    fn interface_is_part_of_key() {
        let mut cache = NeighborCache::new(100);

        cache
            .insert(entry())
            .unwrap();

        let second = NeighborEntry::new(
            ip(192, 168, 1, 1),
            2,
            Some([1, 2, 3, 4, 5, 6]),
            NeighborState::Reachable,
            Some(60),
        );

        cache.insert(second).unwrap();

        assert_eq!(cache.len(), 2);

        assert_eq!(
            cache
                .get(ip(192, 168, 1, 1), 1)
                .unwrap()
                .link_layer_address,
            Some(mac())
        );

        assert_eq!(
            cache
                .get(ip(192, 168, 1, 1), 2)
                .unwrap()
                .link_layer_address,
            Some([1, 2, 3, 4, 5, 6])
        );
    }

    #[test]
    fn invalid_interface_is_rejected() {
        let mut cache = NeighborCache::new(100);

        let neighbor = NeighborEntry::new(
            ip(192, 168, 1, 1),
            0,
            Some(mac()),
            NeighborState::Reachable,
            Some(60),
        );

        assert_eq!(
            cache.insert(neighbor),
            Err(NeighborError::InvalidInterface)
        );
    }

    #[test]
    fn duplicate_insert_is_rejected() {
        let mut cache = NeighborCache::new(100);

        cache.insert(entry()).unwrap();

        assert_eq!(
            cache.insert(entry()),
            Err(NeighborError::AlreadyExists)
        );
    }

    #[test]
    fn upsert_replaces_existing_entry() {
        let mut cache = NeighborCache::new(100);

        cache.insert(entry()).unwrap();

        let replacement = NeighborEntry::new(
            ip(192, 168, 1, 1),
            1,
            Some([9, 8, 7, 6, 5, 4]),
            NeighborState::Stale,
            Some(120),
        );

        cache.upsert(replacement).unwrap();

        let result = cache
            .get(ip(192, 168, 1, 1), 1)
            .unwrap();

        assert_eq!(result.state, NeighborState::Stale);
        assert_eq!(
            result.link_layer_address,
            Some([9, 8, 7, 6, 5, 4])
        );
    }

    #[test]
    fn state_can_be_updated() {
        let mut cache = NeighborCache::new(100);

        cache.insert(entry()).unwrap();

        cache
            .set_state(
                ip(192, 168, 1, 1),
                1,
                NeighborState::Stale,
            )
            .unwrap();

        assert_eq!(
            cache
                .get(ip(192, 168, 1, 1), 1)
                .unwrap()
                .state,
            NeighborState::Stale
        );
    }

    #[test]
    fn remove_entry() {
        let mut cache = NeighborCache::new(100);

        cache.insert(entry()).unwrap();

        assert!(
            cache
                .remove(ip(192, 168, 1, 1), 1)
                .is_some()
        );

        assert!(cache.is_empty());
    }

    #[test]
    fn capacity_is_enforced() {
        let mut cache = NeighborCache::new(1);

        cache.insert(entry()).unwrap();

        let second = NeighborEntry::new(
            ip(192, 168, 1, 2),
            1,
            Some(mac()),
            NeighborState::Reachable,
            Some(60),
        );

        assert_eq!(
            cache.insert(second),
            Err(NeighborError::CapacityExceeded)
        );
    }

    #[test]
    fn ipv6_and_ipv4_do_not_collide() {
        let mut cache = NeighborCache::new(100);

        cache
            .insert(NeighborEntry::new(
                ip(192, 168, 1, 1),
                1,
                Some(mac()),
                NeighborState::Reachable,
                Some(60),
            ))
            .unwrap();

        let ipv6 = NeighborEntry::new(
            "2001:db8::1".parse().unwrap(),
            1,
            Some([1, 2, 3, 4, 5, 6]),
            NeighborState::Reachable,
            Some(60),
        );

        cache.insert(ipv6).unwrap();

        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn failed_neighbor_is_not_resolved() {
        let mut cache = NeighborCache::new(100);

        let mut neighbor = entry();
        neighbor.state = NeighborState::Failed;

        cache.insert(neighbor).unwrap();

        assert_eq!(
            cache.resolve(ip(192, 168, 1, 1), 1),
            Err(NeighborError::NotFound)
        );
    }

    #[test]
    fn missing_neighbor_returns_not_found() {
        let cache = NeighborCache::new(100);

        assert_eq!(
            cache.resolve(ip(10, 0, 0, 1), 1),
            Err(NeighborError::NotFound)
        );
    }
}