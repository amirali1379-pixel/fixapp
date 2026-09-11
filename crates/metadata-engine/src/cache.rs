use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub struct MetadataCache {
    entries: Mutex<HashMap<String, CacheEntry>>,
    max_entries: usize,
}

#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub value: String,
    pub inserted_at: u64,
    pub ttl_secs: u64,
}

impl MetadataCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::with_capacity(max_entries)),
            max_entries,
        }
    }

    pub fn get(&self, key: &str) -> Option<String> {
        let mut entries = self.entries.lock().ok()?;

        let now = unix_seconds();

        let expired = match entries.get(key) {
            Some(entry) => is_expired(entry, now),
            None => return None,
        };

        if expired {
            entries.remove(key);
            return None;
        }

        entries.get(key).map(|entry| entry.value.clone())
    }

    pub fn insert(&self, key: &str, value: &str, ttl_secs: u64) {
        if self.max_entries == 0 {
            return;
        }

        let mut entries = match self.entries.lock() {
            Ok(entries) => entries,
            Err(_) => return,
        };

        let now = unix_seconds();

        if let Some(existing) = entries.get_mut(key) {
            existing.value = value.to_string();
            existing.inserted_at = now;
            existing.ttl_secs = ttl_secs;
            return;
        }

        remove_expired(&mut entries, now);

        if entries.len() >= self.max_entries {
            if let Some(key_to_remove) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.inserted_at)
                .map(|(key, _)| key.clone())
            {
                entries.remove(&key_to_remove);
            }
        }

        entries.insert(
            key.to_string(),
            CacheEntry {
                value: value.to_string(),
                inserted_at: now,
                ttl_secs,
            },
        );
    }

    pub fn remove(&self, key: &str) -> bool {
        self.entries
            .lock()
            .map(|mut entries| entries.remove(key).is_some())
            .unwrap_or(false)
    }

    pub fn clear(&self) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.clear();
        }
    }

    pub fn len(&self) -> usize {
        self.entries.lock().map(|entries| entries.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn is_expired(entry: &CacheEntry, now: u64) -> bool {
    now.saturating_sub(entry.inserted_at) >= entry.ttl_secs
}

fn remove_expired(entries: &mut HashMap<String, CacheEntry>, now: u64) {
    entries.retain(|_, entry| !is_expired(entry, now));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_get() {
        let cache = MetadataCache::new(4);

        cache.insert("a", "value", 60);

        assert_eq!(cache.get("a"), Some("value".to_string()));
    }

    #[test]
    fn missing_key_returns_none() {
        let cache = MetadataCache::new(4);

        assert_eq!(cache.get("missing"), None);
    }

    #[test]
    fn zero_ttl_expires_immediately() {
        let cache = MetadataCache::new(4);

        cache.insert("a", "value", 0);

        assert_eq!(cache.get("a"), None);
    }

    #[test]
    fn capacity_is_bounded() {
        let cache = MetadataCache::new(2);

        cache.insert("a", "1", 60);
        cache.insert("b", "2", 60);
        cache.insert("c", "3", 60);

        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn update_does_not_grow_cache() {
        let cache = MetadataCache::new(2);

        cache.insert("a", "1", 60);
        cache.insert("a", "2", 60);

        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get("a"), Some("2".to_string()));
    }
}