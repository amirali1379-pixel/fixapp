use std::sync::atomic::Ordering;
use network_core::statistics::{DropCategory, EngineStatistics};
use network_core::{EngineError, EngineErrorCode, EngineResult};
use crate::engine::EngineRuntime;

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct UnifiedStatisticsSnapshot {
    pub packets_received: u64,
    pub packets_processed: u64,
    pub bytes_received: u64,
    pub bytes_processed: u64,
    pub actions_applied: u64,
    pub reinjections: u64,
    pub errors: u64,
    pub drops_host_requested: u64,
    pub drops_safety_error: u64,
    pub drops_backend_failure: u64,
    pub queue_saturation_events: u64,
    pub backend_failures: u64,
    pub backend_failovers: u64,
    pub active_flows: u64,
    pub max_flows: u64,
    pub gateway_packets_forwarded: u64,
    pub gateway_packets_dropped: u64,
    pub gateway_nat_translations: u64,
    pub gateway_route_lookups: u64,
    pub gateway_route_failures: u64,
    pub gateway_neighbor_lookups: u64,
    pub gateway_neighbor_failures: u64,
}

impl EngineRuntime {
    pub fn unified_statistics(&self) -> UnifiedStatisticsSnapshot {
        let engine = &self.statistics;
        let (active_flows, max_flows) = match self.flow_table.lock() {
            Ok(table) => (table.len().min(u64::MAX as usize) as u64, table.max_entries().min(u64::MAX as usize) as u64),
            Err(_) => (0, 0),
        };
        UnifiedStatisticsSnapshot {
            packets_received: engine.total_packets_received.load(Ordering::Relaxed),
            packets_processed: engine.total_packets_processed.load(Ordering::Relaxed),
            bytes_received: engine.total_bytes_received.load(Ordering::Relaxed),
            bytes_processed: engine.total_bytes_processed.load(Ordering::Relaxed),
            actions_applied: engine.total_actions_applied.load(Ordering::Relaxed),
            reinjections: engine.total_reinjections.load(Ordering::Relaxed),
            errors: engine.total_errors.load(Ordering::Relaxed),
            drops_host_requested: engine.drops_host_requested.load(Ordering::Relaxed),
            drops_safety_error: engine.drops_safety_error.load(Ordering::Relaxed),
            drops_backend_failure: engine.drops_backend_failure.load(Ordering::Relaxed),
            queue_saturation_events: engine.queue_saturation_events.load(Ordering::Relaxed),
            backend_failures: engine.backend_failures.load(Ordering::Relaxed),
            backend_failovers: engine.backend_failovers.load(Ordering::Relaxed),
            active_flows, max_flows,
            gateway_packets_forwarded: engine.gateway_packets_forwarded.load(Ordering::Relaxed),
            gateway_packets_dropped: engine.gateway_packets_dropped.load(Ordering::Relaxed),
            gateway_nat_translations: engine.gateway_nat_translations.load(Ordering::Relaxed),
            gateway_route_lookups: engine.gateway_route_lookups.load(Ordering::Relaxed),
            gateway_route_failures: engine.gateway_route_failures.load(Ordering::Relaxed),
            gateway_neighbor_lookups: engine.gateway_neighbor_lookups.load(Ordering::Relaxed),
            gateway_neighbor_failures: engine.gateway_neighbor_failures.load(Ordering::Relaxed),
        }
    }

    pub fn record_drop(&self, category: DropCategory, count: u64) -> EngineResult<()> {
        match category {
            DropCategory::HostRequestedDrop => self.statistics.drops_host_requested.fetch_add(count, Ordering::Relaxed),
            DropCategory::SafetyErrorDrop => self.statistics.drops_safety_error.fetch_add(count, Ordering::Relaxed),
            DropCategory::BackendFailure => self.statistics.drops_backend_failure.fetch_add(count, Ordering::Relaxed),
        };
        Ok(())
    }

    pub fn record_queue_saturation(&self) {
        self.statistics.queue_saturation_events.fetch_add(1, Ordering::Relaxed);
    }

    pub fn validate_statistics(&self) -> EngineResult<()> {
        let snapshot = self.unified_statistics();
        if snapshot.packets_processed > snapshot.packets_received || snapshot.bytes_processed > snapshot.bytes_received {
            return Err(EngineError::with_message(EngineErrorCode::InternalError, "processed statistics exceed received statistics"));
        }
        let _ = EngineStatistics::new();
        Ok(())
    }
}
