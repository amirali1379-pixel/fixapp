// dll/network-engine/src/metrics.rs
//
// Engine-side metric primitives.
//
// The authoritative metric primitives live in `network_core::metrics`.
// This module re-exports them for use inside the final DLL and adds a
// small snapshot type for Engine-level metric reporting.
//
// Scope:
// - Pure metric primitives (Counter / Gauge / Histogram).
// - Per-backend metric bundle.
// - Engine-wide metric bundle and snapshot.
//
// This module does NOT:
// - perform packet processing
// - query backends
// - read from Windows host machine state
// - own any policy

#![forbid(unsafe_code)]

pub use network_core::metrics::{
    BackendMetrics,
    Counter,
    EngineMetrics,
    EngineMetricsSnapshot,
    Gauge,
    Histogram,
};

/// Convenience view over the Engine metrics for the Load Balancer and
/// statistics subsystems.
///
/// This is intentionally a thin wrapper: it holds a reference-counted
/// `EngineMetrics` and exposes a snapshot helper.
#[derive(Debug, Clone)]
pub struct MetricsView {
    inner: std::sync::Arc<EngineMetrics>,
}

impl MetricsView {
    pub fn new(inner: std::sync::Arc<EngineMetrics>) -> Self {
        Self { inner }
    }

    /// Returns a point-in-time snapshot of the Engine metrics.
    pub fn snapshot(&self) -> EngineMetricsSnapshot {
        self.inner.snapshot()
    }

    /// Resets every counter, gauge, and histogram back to zero.
    ///
    /// Intended for diagnostics and tests; the Engine does not reset
    /// metrics during normal operation.
    pub fn reset(&self) {
        self.inner.reset();
    }

    /// Returns a reference to the underlying metric bundle.
    pub fn inner(&self) -> &EngineMetrics {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn re_exports_are_usable() {
        let counter = Counter::new();
        counter.increment();
        assert_eq!(counter.get(), 1);

        let gauge = Gauge::new();
        gauge.set(7);
        assert_eq!(gauge.get(), 7);

        let histogram = Histogram::new(vec![10, 100]);
        histogram.observe(5);
        assert_eq!(histogram.count(), 1);
        assert_eq!(histogram.sum(), 5);
    }

    #[test]
    fn metrics_view_snapshot_is_consistent() {
        let metrics = Arc::new(EngineMetrics::new());
        metrics.packets_received.increment_by(4);
        metrics.packets_processed.increment_by(3);
        metrics.packets_dropped.increment_by(1);

        let view = MetricsView::new(Arc::clone(&metrics));
        let snapshot = view.snapshot();

        assert_eq!(snapshot.packets_received, 4);
        assert_eq!(snapshot.packets_processed, 3);
        assert_eq!(snapshot.packets_dropped, 1);
    }

    #[test]
    fn metrics_view_reset_clears_counters() {
        let metrics = Arc::new(EngineMetrics::new());
        metrics.packets_received.increment_by(4);

        let view = MetricsView::new(Arc::clone(&metrics));
        view.reset();

        assert_eq!(view.snapshot().packets_received, 0);
    }

    #[test]
    fn backend_metrics_bundle_is_re_exported() {
        let bundle = BackendMetrics::default();
        assert_eq!(bundle.packets_received.get(), 0);
        assert_eq!(bundle.packets_dropped.get(), 0);
        assert_eq!(bundle.bytes_received.get(), 0);
        assert_eq!(bundle.errors.get(), 0);
    }
}