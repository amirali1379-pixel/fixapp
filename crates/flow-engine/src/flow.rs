#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use crate::counters::FlowCounters;
use crate::key::FlowKey;
use network_core::Direction;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowDirection { Forward, Reverse, Unknown }

impl FlowDirection {
    pub fn from_key(flow_key: &FlowKey, packet_key: &FlowKey) -> Self {
        if flow_key == packet_key { Self::Forward }
        else if flow_key.is_reverse_of(packet_key) { Self::Reverse }
        else { Self::Unknown }
    }

    pub fn from_network_direction(direction: Direction) -> Self {
        match direction {
            Direction::Inbound => Self::Reverse,
            Direction::Outbound => Self::Forward,
            Direction::Unknown => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Flow {
    pub key: FlowKey,

    /// Canonical aggregate observation counters for the Flow Engine.
    pub counters: FlowCounters,

    // Compatibility mirrors retained for the existing Flow API. They are
    // synchronized from `counters` after every packet observation.
    pub packets: u64,
    pub bytes: u64,

    pub forward_packets: u64,
    pub forward_bytes: u64,
    pub reverse_packets: u64,
    pub reverse_bytes: u64,

    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
    pub last_forward_seen_ns: u64,
    pub last_reverse_seen_ns: u64,

    pub state: crate::state::FlowState,
}

impl Flow {
    pub fn new(key: FlowKey) -> Self {
        let now = now_ns();
        Self {
            key,
            counters: FlowCounters::new(),
            packets: 0,
            bytes: 0,
            forward_packets: 0,
            forward_bytes: 0,
            reverse_packets: 0,
            reverse_bytes: 0,
            first_seen_ns: now,
            last_seen_ns: now,
            last_forward_seen_ns: 0,
            last_reverse_seen_ns: 0,
            state: crate::state::FlowState::New,
        }
    }

    pub fn record_packet(&mut self, bytes: usize, direction: FlowDirection, timestamp_ns: Option<u64>) {
        let timestamp = timestamp_ns.unwrap_or_else(now_ns);
        let bytes_u64 = bytes as u64;

        // FlowCounters is the canonical aggregate counter/timestamp source.
        self.counters.record(bytes_u64, timestamp);
        self.packets = self.counters.packets();
        self.bytes = self.counters.bytes();
        self.first_seen_ns = self.counters.first_seen_ns();
        self.last_seen_ns = self.counters.last_seen_ns();

        match direction {
            FlowDirection::Forward => {
                self.forward_packets = self.forward_packets.saturating_add(1);
                self.forward_bytes = self.forward_bytes.saturating_add(bytes_u64);
                self.last_forward_seen_ns = self.last_forward_seen_ns.max(timestamp);
            }
            FlowDirection::Reverse => {
                self.reverse_packets = self.reverse_packets.saturating_add(1);
                self.reverse_bytes = self.reverse_bytes.saturating_add(bytes_u64);
                self.last_reverse_seen_ns = self.last_reverse_seen_ns.max(timestamp);
            }
            FlowDirection::Unknown => {}
        }

        if self.state == crate::state::FlowState::New {
            self.state = crate::state::FlowState::Active;
        }
    }

    pub fn packet_count(&self) -> u64 { self.counters.packets() }
    pub fn byte_count(&self) -> u64 { self.counters.bytes() }

    pub fn age(&self, now_ns: u64) -> Duration {
        if now_ns <= self.first_seen_ns { Duration::ZERO }
        else { Duration::from_nanos(now_ns.saturating_sub(self.first_seen_ns)) }
    }

    pub fn idle_for(&self, now_ns: u64) -> Duration {
        if now_ns <= self.last_seen_ns { Duration::ZERO }
        else { Duration::from_nanos(now_ns.saturating_sub(self.last_seen_ns)) }
    }

    pub fn is_idle(&self, now_ns: u64, timeout: Duration) -> bool { self.idle_for(now_ns) >= timeout }
    pub fn close(&mut self) { self.state = crate::state::FlowState::Closed; }
    pub fn mark_expired(&mut self) { self.state = crate::state::FlowState::Expired; }
    pub fn is_active(&self) -> bool { self.state == crate::state::FlowState::Active }
    pub fn is_closed(&self) -> bool { self.state == crate::state::FlowState::Closed }
    pub fn is_expired(&self) -> bool { self.state == crate::state::FlowState::Expired }
    pub fn duration_ns(&self) -> u64 { self.last_seen_ns.saturating_sub(self.first_seen_ns) }
    pub fn average_packet_size(&self) -> u64 {
        let packets = self.counters.packets();
        if packets == 0 { 0 } else { self.counters.bytes() / packets }
    }

    pub fn counters(&self) -> &FlowCounters { &self.counters }
}

fn now_ns() -> u64 {
    static BASELINE: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let baseline = BASELINE.get_or_init(Instant::now);
    baseline.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> FlowKey {
        FlowKey::new("192.168.1.10".parse().unwrap(), "8.8.8.8".parse().unwrap(), 12345, 443, 6)
    }

    #[test]
    fn creates_new_flow() {
        let flow = Flow::new(test_key());
        assert_eq!(flow.packets, 0);
        assert_eq!(flow.bytes, 0);
        assert_eq!(flow.counters.packets(), 0);
        assert_eq!(flow.state, crate::state::FlowState::New);
    }

    #[test]
    fn counters_are_canonical_for_aggregate_observations() {
        let mut flow = Flow::new(test_key());
        flow.record_packet(1500, FlowDirection::Forward, Some(100));
        flow.record_packet(500, FlowDirection::Reverse, Some(200));
        assert_eq!(flow.counters.packets(), 2);
        assert_eq!(flow.counters.bytes(), 2000);
        assert_eq!(flow.counters.first_seen_ns(), 100);
        assert_eq!(flow.counters.last_seen_ns(), 200);
        assert_eq!(flow.packet_count(), 2);
        assert_eq!(flow.byte_count(), 2000);
    }

    #[test]
    fn direction_counters_are_preserved() {
        let mut flow = Flow::new(test_key());
        flow.record_packet(1000, FlowDirection::Forward, Some(100));
        flow.record_packet(500, FlowDirection::Reverse, Some(200));
        assert_eq!(flow.forward_packets, 1);
        assert_eq!(flow.forward_bytes, 1000);
        assert_eq!(flow.reverse_packets, 1);
        assert_eq!(flow.reverse_bytes, 500);
    }
}
