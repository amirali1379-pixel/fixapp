use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct Counter {
    value: AtomicU64,
}

impl Counter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn increment(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_by(&self, value: u64) {
        self.value.fetch_add(value, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }

    pub fn reset(&self) {
        self.value.store(0, Ordering::Relaxed);
    }
}

#[derive(Debug, Default)]
pub struct Gauge {
    value: AtomicU64,
}

impl Gauge {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, value: u64) {
        self.value.store(value, Ordering::Relaxed);
    }

    pub fn increment(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn decrement(&self) {
        let _ = self.value.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |value| value.checked_sub(1),
        );
    }

    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

#[derive(Debug)]
pub struct Histogram {
    buckets: Vec<u64>,
    counts: Vec<AtomicU64>,
    sum: AtomicU64,
    count: AtomicU64,
}

impl Histogram {
    pub fn new(mut buckets: Vec<u64>) -> Self {
        buckets.sort_unstable();
        buckets.dedup();

        let counts = (0..=buckets.len())
            .map(|_| AtomicU64::new(0))
            .collect();

        Self {
            buckets,
            counts,
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    pub fn observe(&self, value: u64) {
        self.sum.fetch_add(value, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);

        let index = self
            .buckets
            .iter()
            .position(|bucket| value <= *bucket)
            .unwrap_or(self.buckets.len());

        self.counts[index].fetch_add(1, Ordering::Relaxed);
    }

    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    pub fn sum(&self) -> u64 {
        self.sum.load(Ordering::Relaxed)
    }

    pub fn buckets(&self) -> &[u64] {
        &self.buckets
    }

    pub fn bucket_count(&self, index: usize) -> Option<u64> {
        self.counts
            .get(index)
            .map(|value| value.load(Ordering::Relaxed))
    }

    pub fn reset(&self) {
        self.sum.store(0, Ordering::Relaxed);
        self.count.store(0, Ordering::Relaxed);

        for count in &self.counts {
            count.store(0, Ordering::Relaxed);
        }
    }
}

#[derive(Debug)]
pub struct BackendMetrics {
    pub packets_received: Counter,
    pub packets_dropped: Counter,
    pub bytes_received: Counter,
    pub errors: Counter,
}

impl Default for BackendMetrics {
    fn default() -> Self {
        Self {
            packets_received: Counter::new(),
            packets_dropped: Counter::new(),
            bytes_received: Counter::new(),
            errors: Counter::new(),
        }
    }
}

#[derive(Debug)]
pub struct EngineMetrics {
    pub packets_received: Counter,
    pub packets_processed: Counter,
    pub packets_dropped: Counter,
    pub packets_forwarded: Counter,

    pub bytes_received: Counter,
    pub bytes_processed: Counter,
    pub bytes_forwarded: Counter,

    pub malformed_packets: Counter,
    pub queue_full: Counter,
    pub buffer_exhausted: Counter,

    pub active_flows: Gauge,

    pub action_pass: Counter,
    pub action_drop: Counter,
    pub action_modify: Counter,
    pub action_reinject: Counter,

    pub packet_processing_time_ns: Histogram,
}

impl Default for EngineMetrics {
    fn default() -> Self {
        Self {
            packets_received: Counter::new(),
            packets_processed: Counter::new(),
            packets_dropped: Counter::new(),
            packets_forwarded: Counter::new(),

            bytes_received: Counter::new(),
            bytes_processed: Counter::new(),
            bytes_forwarded: Counter::new(),

            malformed_packets: Counter::new(),
            queue_full: Counter::new(),
            buffer_exhausted: Counter::new(),

            active_flows: Gauge::new(),

            action_pass: Counter::new(),
            action_drop: Counter::new(),
            action_modify: Counter::new(),
            action_reinject: Counter::new(),

            packet_processing_time_ns: Histogram::new(vec![
                1_000,
                5_000,
                10_000,
                50_000,
                100_000,
                500_000,
                1_000_000,
                5_000_000,
                10_000_000,
            ]),
        }
    }
}

impl EngineMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset(&self) {
        self.packets_received.reset();
        self.packets_processed.reset();
        self.packets_dropped.reset();
        self.packets_forwarded.reset();

        self.bytes_received.reset();
        self.bytes_processed.reset();
        self.bytes_forwarded.reset();

        self.malformed_packets.reset();
        self.queue_full.reset();
        self.buffer_exhausted.reset();

        self.active_flows.set(0);

        self.action_pass.reset();
        self.action_drop.reset();
        self.action_modify.reset();
        self.action_reinject.reset();

        self.packet_processing_time_ns.reset();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineMetricsSnapshot {
    pub packets_received: u64,
    pub packets_processed: u64,
    pub packets_dropped: u64,
    pub packets_forwarded: u64,

    pub bytes_received: u64,
    pub bytes_processed: u64,
    pub bytes_forwarded: u64,

    pub malformed_packets: u64,
    pub queue_full: u64,
    pub buffer_exhausted: u64,

    pub active_flows: u64,

    pub action_pass: u64,
    pub action_drop: u64,
    pub action_modify: u64,
    pub action_reinject: u64,

    pub processing_count: u64,
    pub processing_time_sum_ns: u64,
}

impl EngineMetrics {
    pub fn snapshot(&self) -> EngineMetricsSnapshot {
        EngineMetricsSnapshot {
            packets_received: self.packets_received.get(),
            packets_processed: self.packets_processed.get(),
            packets_dropped: self.packets_dropped.get(),
            packets_forwarded: self.packets_forwarded.get(),

            bytes_received: self.bytes_received.get(),
            bytes_processed: self.bytes_processed.get(),
            bytes_forwarded: self.bytes_forwarded.get(),

            malformed_packets: self.malformed_packets.get(),
            queue_full: self.queue_full.get(),
            buffer_exhausted: self.buffer_exhausted.get(),

            active_flows: self.active_flows.get(),

            action_pass: self.action_pass.get(),
            action_drop: self.action_drop.get(),
            action_modify: self.action_modify.get(),
            action_reinject: self.action_reinject.get(),

            processing_count: self.packet_processing_time_ns.count(),
            processing_time_sum_ns: self.packet_processing_time_ns.sum(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_works() {
        let counter = Counter::new();

        counter.increment();
        counter.increment_by(4);

        assert_eq!(counter.get(), 5);

        counter.reset();

        assert_eq!(counter.get(), 0);
    }

    #[test]
    fn gauge_works() {
        let gauge = Gauge::new();

        gauge.set(10);
        assert_eq!(gauge.get(), 10);

        gauge.increment();
        assert_eq!(gauge.get(), 11);

        gauge.decrement();
        assert_eq!(gauge.get(), 10);

        gauge.set(0);
        gauge.decrement();

        assert_eq!(gauge.get(), 0);
    }

    #[test]
    fn histogram_works() {
        let histogram = Histogram::new(vec![10, 20, 50]);

        histogram.observe(5);
        histogram.observe(10);
        histogram.observe(25);
        histogram.observe(100);

        assert_eq!(histogram.count(), 4);
        assert_eq!(histogram.sum(), 140);

        assert_eq!(histogram.bucket_count(0), Some(2));
        assert_eq!(histogram.bucket_count(1), Some(0));
        assert_eq!(histogram.bucket_count(2), Some(1));
        assert_eq!(histogram.bucket_count(3), Some(1));
    }

    #[test]
    fn histogram_sorts_and_deduplicates_buckets() {
        let histogram = Histogram::new(vec![50, 10, 20, 20, 10]);

        assert_eq!(histogram.buckets(), &[10, 20, 50]);
    }

    #[test]
    fn histogram_reset_works() {
        let histogram = Histogram::new(vec![10, 20]);

        histogram.observe(5);
        histogram.observe(15);

        histogram.reset();

        assert_eq!(histogram.count(), 0);
        assert_eq!(histogram.sum(), 0);
        assert_eq!(histogram.bucket_count(0), Some(0));
        assert_eq!(histogram.bucket_count(1), Some(0));
        assert_eq!(histogram.bucket_count(2), Some(0));
    }

    #[test]
    fn engine_metrics_snapshot_works() {
        let metrics = EngineMetrics::new();

        metrics.packets_received.increment_by(10);
        metrics.bytes_received.increment_by(1000);
        metrics.packets_processed.increment_by(8);
        metrics.packets_dropped.increment_by(2);
        metrics.active_flows.set(4);
        metrics.action_pass.increment_by(6);
        metrics.action_drop.increment_by(2);
        metrics.packet_processing_time_ns.observe(5000);

        let snapshot = metrics.snapshot();

        assert_eq!(snapshot.packets_received, 10);
        assert_eq!(snapshot.bytes_received, 1000);
        assert_eq!(snapshot.packets_processed, 8);
        assert_eq!(snapshot.packets_dropped, 2);
        assert_eq!(snapshot.active_flows, 4);
        assert_eq!(snapshot.action_pass, 6);
        assert_eq!(snapshot.action_drop, 2);
        assert_eq!(snapshot.processing_count, 1);
        assert_eq!(snapshot.processing_time_sum_ns, 5000);
    }

    #[test]
    fn backend_metrics_start_zero() {
        let metrics = BackendMetrics::default();

        assert_eq!(metrics.packets_received.get(), 0);
        assert_eq!(metrics.packets_dropped.get(), 0);
        assert_eq!(metrics.bytes_received.get(), 0);
        assert_eq!(metrics.errors.get(), 0);
    }
}