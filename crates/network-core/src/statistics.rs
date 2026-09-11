use std::sync::atomic::{AtomicU64, Ordering};

/// Per-backend statistics.
///
/// All counters are monotonically increasing u64 values.
#[derive(Debug)]
pub struct BackendStatistics {
    pub backend_name: String,
    pub packets_received: AtomicU64,
    pub packets_sent: AtomicU64,
    pub packets_dropped: AtomicU64,
    pub packets_modified: AtomicU64,
    pub packets_reinjected: AtomicU64,
    pub bytes_received: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub errors: AtomicU64,
    pub queue_depth: AtomicU64,
    pub active_connections: AtomicU64,
}

impl BackendStatistics {
    pub fn new(backend_name: impl Into<String>) -> Self {
        Self {
            backend_name: backend_name.into(),
            packets_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            packets_modified: AtomicU64::new(0),
            packets_reinjected: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            queue_depth: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
        }
    }

    pub fn snapshot(&self) -> BackendStatisticsSnapshot {
        BackendStatisticsSnapshot {
            backend_name: self.backend_name.clone(),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_dropped: self.packets_dropped.load(Ordering::Relaxed),
            packets_modified: self.packets_modified.load(Ordering::Relaxed),
            packets_reinjected: self.packets_reinjected.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            queue_depth: self.queue_depth.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BackendStatisticsSnapshot {
    pub backend_name: String,
    pub packets_received: u64,
    pub packets_sent: u64,
    pub packets_dropped: u64,
    pub packets_modified: u64,
    pub packets_reinjected: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub errors: u64,
    pub queue_depth: u64,
    pub active_connections: u64,
}

/// Drop categories that MUST remain distinct.
///
/// TASK-0015: Statistics MUST distinguish:
/// - HostRequestedDrop
/// - SafetyErrorDrop
/// - BackendFailure
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DropCategory {
    /// Host explicitly requested this packet be dropped.
    HostRequestedDrop,

    /// Engine dropped due to safety or internal error.
    SafetyErrorDrop,

    /// Backend failure caused the drop.
    BackendFailure,
}

impl DropCategory {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::HostRequestedDrop => "host-requested",
            Self::SafetyErrorDrop => "safety-error",
            Self::BackendFailure => "backend-failure",
        }
    }
}

/// Global engine statistics.
///
/// Drop categories are tracked separately to ensure no silent
/// packet loss and no arbitrary engine-generated DROP.
#[derive(Debug)]
pub struct EngineStatistics {
    pub total_packets_received: AtomicU64,
    pub total_packets_processed: AtomicU64,
    pub total_bytes_received: AtomicU64,
    pub total_bytes_processed: AtomicU64,
    pub total_actions_applied: AtomicU64,
    pub total_reinjections: AtomicU64,
    pub total_errors: AtomicU64,

    // Host-facing packet action counters.
    pub packets_forwarded: AtomicU64,
    pub modifications_applied: AtomicU64,

    // Drop categories (TASK-0015)
    pub drops_host_requested: AtomicU64,
    pub drops_safety_error: AtomicU64,
    pub drops_backend_failure: AtomicU64,

    pub queue_saturation_events: AtomicU64,
    pub backend_failures: AtomicU64,
    pub backend_failovers: AtomicU64,

    // Gateway-specific
    pub gateway_packets_forwarded: AtomicU64,
    pub gateway_packets_dropped: AtomicU64,
    pub gateway_nat_translations: AtomicU64,
    pub gateway_route_lookups: AtomicU64,
    pub gateway_route_failures: AtomicU64,
    pub gateway_neighbor_lookups: AtomicU64,
    pub gateway_neighbor_failures: AtomicU64,
}

impl EngineStatistics {
    pub fn new() -> Self {
        Self {
            total_packets_received: AtomicU64::new(0),
            total_packets_processed: AtomicU64::new(0),
            total_bytes_received: AtomicU64::new(0),
            total_bytes_processed: AtomicU64::new(0),
            total_actions_applied: AtomicU64::new(0),
            total_reinjections: AtomicU64::new(0),
            total_errors: AtomicU64::new(0),
            packets_forwarded: AtomicU64::new(0),
            modifications_applied: AtomicU64::new(0),
            drops_host_requested: AtomicU64::new(0),
            drops_safety_error: AtomicU64::new(0),
            drops_backend_failure: AtomicU64::new(0),
            queue_saturation_events: AtomicU64::new(0),
            backend_failures: AtomicU64::new(0),
            backend_failovers: AtomicU64::new(0),
            gateway_packets_forwarded: AtomicU64::new(0),
            gateway_packets_dropped: AtomicU64::new(0),
            gateway_nat_translations: AtomicU64::new(0),
            gateway_route_lookups: AtomicU64::new(0),
            gateway_route_failures: AtomicU64::new(0),
            gateway_neighbor_lookups: AtomicU64::new(0),
            gateway_neighbor_failures: AtomicU64::new(0),
        }
    }

    pub fn record_packet_received(&self, bytes: u64) {
        self.total_packets_received.fetch_add(1, Ordering::Relaxed);
        self.total_bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_packet_processed(&self, bytes: u64) {
        self.total_packets_processed.fetch_add(1, Ordering::Relaxed);
        self.total_bytes_processed.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_action_applied(&self) {
        self.total_actions_applied.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_reinjection(&self) {
        self.total_reinjections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_error(&self) {
        self.total_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_forwarded(&self) {
        self.packets_forwarded.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_modification(&self) {
        self.modifications_applied.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a drop with its specific category.
    ///
    /// DROP categories MUST remain distinct per TASK-0015.
    pub fn record_drop(&self, category: DropCategory) {
        match category {
            DropCategory::HostRequestedDrop => self.drops_host_requested.fetch_add(1, Ordering::Relaxed),
            DropCategory::SafetyErrorDrop => self.drops_safety_error.fetch_add(1, Ordering::Relaxed),
            DropCategory::BackendFailure => self.drops_backend_failure.fetch_add(1, Ordering::Relaxed),
        };
    }

    pub fn record_queue_saturation(&self) {
        self.queue_saturation_events.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_backend_failure(&self) {
        self.backend_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_backend_failover(&self) {
        self.backend_failovers.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_gateway_forward(&self) {
        self.gateway_packets_forwarded.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_gateway_drop(&self) {
        self.gateway_packets_dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_nat_translation(&self) {
        self.gateway_nat_translations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_route_lookup(&self, success: bool) {
        self.gateway_route_lookups.fetch_add(1, Ordering::Relaxed);
        if !success {
            self.gateway_route_failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_neighbor_lookup(&self, success: bool) {
        self.gateway_neighbor_lookups.fetch_add(1, Ordering::Relaxed);
        if !success {
            self.gateway_neighbor_failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn snapshot(&self) -> EngineStatisticsSnapshot {
        EngineStatisticsSnapshot {
            total_packets_received: self.total_packets_received.load(Ordering::Relaxed),
            total_packets_processed: self.total_packets_processed.load(Ordering::Relaxed),
            total_bytes_received: self.total_bytes_received.load(Ordering::Relaxed),
            total_bytes_processed: self.total_bytes_processed.load(Ordering::Relaxed),
            total_actions_applied: self.total_actions_applied.load(Ordering::Relaxed),
            total_reinjections: self.total_reinjections.load(Ordering::Relaxed),
            total_errors: self.total_errors.load(Ordering::Relaxed),
            drops_host_requested: self.drops_host_requested.load(Ordering::Relaxed),
            drops_safety_error: self.drops_safety_error.load(Ordering::Relaxed),
            drops_backend_failure: self.drops_backend_failure.load(Ordering::Relaxed),
            queue_saturation_events: self.queue_saturation_events.load(Ordering::Relaxed),
            backend_failures: self.backend_failures.load(Ordering::Relaxed),
            backend_failovers: self.backend_failovers.load(Ordering::Relaxed),
            gateway_packets_forwarded: self.gateway_packets_forwarded.load(Ordering::Relaxed),
            gateway_packets_dropped: self.gateway_packets_dropped.load(Ordering::Relaxed),
            gateway_nat_translations: self.gateway_nat_translations.load(Ordering::Relaxed),
            gateway_route_lookups: self.gateway_route_lookups.load(Ordering::Relaxed),
            gateway_route_failures: self.gateway_route_failures.load(Ordering::Relaxed),
            gateway_neighbor_lookups: self.gateway_neighbor_lookups.load(Ordering::Relaxed),
            gateway_neighbor_failures: self.gateway_neighbor_failures.load(Ordering::Relaxed),
        }
    }
}

impl Default for EngineStatistics {
    fn default() -> Self { Self::new() }
}

#[derive(Debug, Clone)]
pub struct EngineStatisticsSnapshot {
    pub total_packets_received: u64,
    pub total_packets_processed: u64,
    pub total_bytes_received: u64,
    pub total_bytes_processed: u64,
    pub total_actions_applied: u64,
    pub total_reinjections: u64,
    pub total_errors: u64,
    pub drops_host_requested: u64,
    pub drops_safety_error: u64,
    pub drops_backend_failure: u64,
    pub queue_saturation_events: u64,
    pub backend_failures: u64,
    pub backend_failovers: u64,
    pub gateway_packets_forwarded: u64,
    pub gateway_packets_dropped: u64,
    pub gateway_nat_translations: u64,
    pub gateway_route_lookups: u64,
    pub gateway_route_failures: u64,
    pub gateway_neighbor_lookups: u64,
    pub gateway_neighbor_failures: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drop_categories_are_distinct() {
        let stats = EngineStatistics::new();
        stats.record_drop(DropCategory::HostRequestedDrop);
        stats.record_drop(DropCategory::HostRequestedDrop);
        stats.record_drop(DropCategory::SafetyErrorDrop);
        stats.record_drop(DropCategory::BackendFailure);
        let snap = stats.snapshot();
        assert_eq!(snap.drops_host_requested, 2);
        assert_eq!(snap.drops_safety_error, 1);
        assert_eq!(snap.drops_backend_failure, 1);
    }

    #[test]
    fn backend_statistics_snapshot() {
        let stats = BackendStatistics::new("WinDivert");
        stats.packets_received.fetch_add(10, Ordering::Relaxed);
        stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
        stats.errors.fetch_add(2, Ordering::Relaxed);
        let snap = stats.snapshot();
        assert_eq!(snap.backend_name, "WinDivert");
        assert_eq!(snap.packets_received, 10);
        assert_eq!(snap.packets_dropped, 1);
        assert_eq!(snap.errors, 2);
    }

    #[test]
    fn gateway_stats_tracked() {
        let stats = EngineStatistics::new();
        stats.record_gateway_forward();
        stats.record_gateway_forward();
        stats.record_gateway_drop();
        stats.record_nat_translation();
        stats.record_route_lookup(true);
        stats.record_route_lookup(false);
        stats.record_neighbor_lookup(true);
        stats.record_neighbor_lookup(false);
        let snap = stats.snapshot();
        assert_eq!(snap.gateway_packets_forwarded, 2);
        assert_eq!(snap.gateway_packets_dropped, 1);
        assert_eq!(snap.gateway_nat_translations, 1);
        assert_eq!(snap.gateway_route_lookups, 2);
        assert_eq!(snap.gateway_route_failures, 1);
        assert_eq!(snap.gateway_neighbor_lookups, 2);
        assert_eq!(snap.gateway_neighbor_failures, 1);
    }

    #[test]
    fn queue_saturation_tracked() {
        let stats = EngineStatistics::new();
        stats.record_queue_saturation();
        stats.record_queue_saturation();
        assert_eq!(stats.snapshot().queue_saturation_events, 2);
    }
}
