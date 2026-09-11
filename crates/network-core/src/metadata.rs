use std::collections::HashMap;

use crate::ObservationId;

#[derive(Debug, Clone, Default)]
pub struct PacketMetadata {
    pub annotations: Vec<MetadataAnnotation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataAnnotation {
    pub key: String,
    pub value: String,
    pub provenance: String,
}

impl PacketMetadata {
    pub fn add(&mut self, key: &str, value: &str, provenance: &str) {
        let key = normalize_key(key);
        let value = normalize_value(value);
        if key.is_empty() || value.is_empty() { return; }

        if let Some(existing) = self.annotations.iter_mut().find(|item| item.key == key && item.value == value) {
            merge_provenance(&mut existing.provenance, provenance);
            return;
        }

        // A key may have multiple values, but the same key/value pair is
        // authoritative only once. Conflicts remain visible instead of being
        // silently overwritten, and every value keeps its provenance.
        self.annotations.push(MetadataAnnotation { key, value, provenance: normalize_provenance(provenance) });
    }

    pub fn merge(&mut self, other: &PacketMetadata) {
        for annotation in &other.annotations {
            self.add(&annotation.key, &annotation.value, &annotation.provenance);
        }
    }

    pub fn values_for(&self, key: &str) -> impl Iterator<Item = &MetadataAnnotation> {
        let normalized = normalize_key(key);
        self.annotations.iter().filter(move |item| item.key == normalized)
    }

    pub fn get(&self, key: &str) -> Option<&MetadataAnnotation> {
        self.values_for(key).next()
    }
}

/// Engine-owned metadata state keyed by the authoritative ObservationId.
/// Packet bytes are never stored or modified here.
#[derive(Debug, Clone, Default)]
pub struct MetadataStore {
    observations: HashMap<ObservationId, PacketMetadata>,
}

impl MetadataStore {
    pub fn new() -> Self { Self::default() }

    pub fn update(&mut self, id: ObservationId, metadata: PacketMetadata) {
        self.observations.entry(id).or_default().merge(&metadata);
    }

    pub fn add(&mut self, id: ObservationId, key: &str, value: &str, provenance: &str) {
        self.observations.entry(id).or_default().add(key, value, provenance);
    }

    pub fn get(&self, id: ObservationId) -> Option<&PacketMetadata> { self.observations.get(&id) }
    pub fn get_mut(&mut self, id: ObservationId) -> Option<&mut PacketMetadata> { self.observations.get_mut(&id) }
    pub fn remove(&mut self, id: ObservationId) -> Option<PacketMetadata> { self.observations.remove(&id) }
    pub fn len(&self) -> usize { self.observations.len() }
    pub fn is_empty(&self) -> bool { self.observations.is_empty() }
    pub fn clear(&mut self) { self.observations.clear(); }

    pub fn ids(&self) -> impl Iterator<Item = ObservationId> + '_ { self.observations.keys().copied() }
}

fn normalize_key(value: &str) -> String { value.trim().to_ascii_lowercase() }
fn normalize_value(value: &str) -> String { value.trim().to_string() }

fn normalize_provenance(value: &str) -> String {
    let mut normalized = String::new();
    for part in value.split(',').map(str::trim).filter(|part| !part.is_empty()) {
        if normalized.split(',').any(|existing| existing == part) { continue; }
        if !normalized.is_empty() { normalized.push(','); }
        normalized.push_str(part);
    }
    normalized
}

fn merge_provenance(existing: &mut String, incoming: &str) {
    for provenance in incoming.split(',').map(str::trim).filter(|part| !part.is_empty()) {
        if existing.split(',').any(|current| current == provenance) { continue; }
        if !existing.is_empty() { existing.push(','); }
        existing.push_str(provenance);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_values_merge_provenance() {
        let mut metadata = PacketMetadata::default();
        metadata.add(" HostName ", " example.test ", "dns");
        metadata.add("hostname", "example.test", "cache");
        assert_eq!(metadata.annotations.len(), 1);
        assert_eq!(metadata.annotations[0].key, "hostname");
        assert!(metadata.annotations[0].provenance.contains("dns"));
        assert!(metadata.annotations[0].provenance.contains("cache"));
    }

    #[test]
    fn duplicate_provenance_is_not_repeated() {
        let mut metadata = PacketMetadata::default();
        metadata.add("hostname", "example.test", "dns,cache");
        metadata.add("hostname", "example.test", "dns,etw");
        assert_eq!(metadata.annotations[0].provenance, "dns,cache,etw");
    }

    #[test]
    fn conflicting_values_are_preserved() {
        let mut metadata = PacketMetadata::default();
        metadata.add("hostname", "one.example", "dns-a");
        metadata.add("hostname", "two.example", "dns-b");
        assert_eq!(metadata.annotations.len(), 2);
    }

    #[test]
    fn observation_lookup_is_isolated() {
        let mut store = MetadataStore::new();
        let first = ObservationId::new(1);
        let second = ObservationId::new(2);
        store.add(first, "source", "npcap", "capture");
        assert!(store.get(first).is_some());
        assert!(store.get(second).is_none());
    }
}
