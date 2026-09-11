#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicU64, Ordering};

/// Thread-safe aggregate observation counters owned by a flow.
///
/// The counter set is the canonical source for packet/byte totals and
/// first/last observation timestamps. Updates are saturating so malformed or
/// adversarial input cannot wrap aggregate statistics.
#[derive(Debug, Default)]
pub struct FlowCounters {
    packets: AtomicU64,
    bytes: AtomicU64,
    first_seen_ns: AtomicU64,
    last_seen_ns: AtomicU64,
}

impl FlowCounters {
    pub const fn new() -> Self {
        Self {
            packets: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            first_seen_ns: AtomicU64::new(0),
            last_seen_ns: AtomicU64::new(0),
        }
    }

    pub fn record(&self, bytes: u64, timestamp_ns: u64) {
        saturating_add(&self.packets, 1);
        saturating_add(&self.bytes, bytes);
        self.update_first_seen(timestamp_ns);
        self.update_last_seen(timestamp_ns);
    }

    pub fn packets(&self) -> u64 { self.packets.load(Ordering::Relaxed) }
    pub fn bytes(&self) -> u64 { self.bytes.load(Ordering::Relaxed) }
    pub fn first_seen_ns(&self) -> u64 { self.first_seen_ns.load(Ordering::Relaxed) }
    pub fn last_seen_ns(&self) -> u64 { self.last_seen_ns.load(Ordering::Relaxed) }

    fn update_first_seen(&self, timestamp_ns: u64) {
        let mut current = self.first_seen_ns.load(Ordering::Relaxed);
        loop {
            if current != 0 && timestamp_ns >= current { return; }
            match self.first_seen_ns.compare_exchange_weak(
                current, timestamp_ns, Ordering::Relaxed, Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }

    fn update_last_seen(&self, timestamp_ns: u64) {
        let mut current = self.last_seen_ns.load(Ordering::Relaxed);
        loop {
            if timestamp_ns <= current { return; }
            match self.last_seen_ns.compare_exchange_weak(
                current, timestamp_ns, Ordering::Relaxed, Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }
}

fn saturating_add(counter: &AtomicU64, value: u64) {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let next = current.saturating_add(value);
        match counter.compare_exchange_weak(
            current, next, Ordering::Relaxed, Ordering::Relaxed,
        ) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

impl Clone for FlowCounters {
    fn clone(&self) -> Self {
        let clone = Self::new();
        clone.packets.store(self.packets(), Ordering::Relaxed);
        clone.bytes.store(self.bytes(), Ordering::Relaxed);
        clone.first_seen_ns.store(self.first_seen_ns(), Ordering::Relaxed);
        clone.last_seen_ns.store(self.last_seen_ns(), Ordering::Relaxed);
        clone
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_counters_and_timestamps() {
        let counters = FlowCounters::new();
        counters.record(1500, 200);
        counters.record(500, 100);
        counters.record(1000, 300);
        assert_eq!(counters.packets(), 3);
        assert_eq!(counters.bytes(), 3000);
        assert_eq!(counters.first_seen_ns(), 100);
        assert_eq!(counters.last_seen_ns(), 300);
    }

    #[test]
    fn default_is_empty() {
        let counters = FlowCounters::default();
        assert_eq!(counters.packets(), 0);
        assert_eq!(counters.bytes(), 0);
        assert_eq!(counters.first_seen_ns(), 0);
        assert_eq!(counters.last_seen_ns(), 0);
    }

    #[test]
    fn aggregate_updates_saturate() {
        let counters = FlowCounters::new();
        counters.packets.store(u64::MAX, Ordering::Relaxed);
        counters.bytes.store(u64::MAX, Ordering::Relaxed);
        counters.record(u64::MAX, 1);
        assert_eq!(counters.packets(), u64::MAX);
        assert_eq!(counters.bytes(), u64::MAX);
    }
}
