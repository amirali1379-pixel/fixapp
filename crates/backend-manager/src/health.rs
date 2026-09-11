#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

/// Health state of an individual backend.
///
/// Health is independent from backend lifecycle.
///
/// For example:
/// - lifecycle = Running + health = Degraded
/// - lifecycle = Running + health = Healthy
/// - lifecycle = Failed + health = Unhealthy
///
/// The BackendManager is responsible for combining lifecycle and health
/// when determining whether a backend is actually selectable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BackendHealth {
    /// No health observation is available yet.
    Unknown = 0,

    /// Backend is operating normally.
    Healthy = 1,

    /// Backend is still potentially usable, but failures have been
    /// observed and it should be treated with lower preference.
    Degraded = 2,

    /// Backend has exceeded its failure threshold and should not be
    /// selected as an available backend.
    Unhealthy = 3,
}

impl BackendHealth {
    pub fn is_healthy(self) -> bool {
        self == Self::Healthy
    }

    /// Returns whether the health state alone permits use.
    ///
    /// This does NOT mean the backend lifecycle is Running.
    /// Lifecycle availability must be checked separately.
    pub fn is_available(self) -> bool {
        matches!(
            self,
            Self::Healthy | Self::Degraded
        )
    }

    pub fn is_failed(self) -> bool {
        self == Self::Unhealthy
    }

    pub fn is_unknown(self) -> bool {
        self == Self::Unknown
    }

    pub fn is_degraded(self) -> bool {
        self == Self::Degraded
    }
}

/// Tracks backend health using consecutive success/failure observations.
///
/// This monitor intentionally does not perform native backend probing.
/// The backend implementation / Engine supplies observations through
/// `record_success()` and `record_failure()`.
///
/// Health state is runtime information only. It does not define packet
/// policy and does not itself cause DROP/PASS/MODIFY/reinject actions.
#[derive(Debug)]
pub struct HealthMonitor {
    failure_threshold: u32,
    recovery_threshold: u32,

    /// Consecutive failures since the last successful observation.
    failures: u32,

    /// Consecutive successful observations since the last failure.
    recoveries: u32,

    health: BackendHealth,

    last_check: Option<Instant>,
    last_failure: Option<Instant>,
    last_recovery: Option<Instant>,
}

impl HealthMonitor {
    /// Creates a health monitor.
    ///
    /// Thresholds are clamped to at least one so that zero cannot
    /// accidentally disable failure or recovery transitions.
    pub fn new(
        failure_threshold: u32,
        recovery_threshold: u32,
    ) -> Self {
        Self {
            failure_threshold: failure_threshold.max(1),
            recovery_threshold: recovery_threshold.max(1),
            failures: 0,
            recoveries: 0,
            health: BackendHealth::Unknown,
            last_check: None,
            last_failure: None,
            last_recovery: None,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(3, 2)
    }

    pub fn health(&self) -> BackendHealth {
        self.health
    }

    pub fn failures(&self) -> u32 {
        self.failures
    }

    pub fn recoveries(&self) -> u32 {
        self.recoveries
    }

    pub fn failure_threshold(&self) -> u32 {
        self.failure_threshold
    }

    pub fn recovery_threshold(&self) -> u32 {
        self.recovery_threshold
    }

    pub fn last_check(&self) -> Option<Instant> {
        self.last_check
    }

    pub fn last_failure(&self) -> Option<Instant> {
        self.last_failure
    }

    pub fn last_recovery(&self) -> Option<Instant> {
        self.last_recovery
    }

    /// Records one successful health observation.
    ///
    /// State behavior:
    ///
    /// ```text
    /// Unknown
    ///   └─ success ─→ Healthy
    ///
    /// Healthy
    ///   └─ success ─→ Healthy
    ///
    /// Degraded
    ///   ├─ success (< recovery threshold) → Degraded
    ///   └─ success (>= recovery threshold) → Healthy
    ///
    /// Unhealthy
    ///   ├─ success (< recovery threshold) → Degraded
    ///   └─ success (>= recovery threshold) → Healthy
    /// ```
    ///
    /// An Unknown backend becomes Healthy after its first successful
    /// observation because there is no evidence of failure. The
    /// recovery threshold applies to recovery from Degraded/Unhealthy,
    /// not initial discovery.
    pub fn record_success(&mut self) -> BackendHealth {
        let now = Instant::now();

        self.last_check = Some(now);
        self.last_recovery = Some(now);

        // A success breaks the consecutive failure sequence.
        self.failures = 0;

        match self.health {
            BackendHealth::Unknown => {
                self.recoveries = 1;
                self.health = BackendHealth::Healthy;
            }

            BackendHealth::Healthy => {
                self.recoveries = self.recoveries.saturating_add(1);
                self.health = BackendHealth::Healthy;
            }

            BackendHealth::Degraded
            | BackendHealth::Unhealthy => {
                self.recoveries =
                    self.recoveries.saturating_add(1);

                if self.recoveries >= self.recovery_threshold {
                    self.health = BackendHealth::Healthy;
                } else {
                    self.health = BackendHealth::Degraded;
                }
            }
        }

        self.health
    }

    /// Records one failed health observation.
    ///
    /// Consecutive failures move:
    ///
    /// ```text
    /// Unknown  ──failure──→ Degraded
    /// Healthy  ──failure──→ Degraded
    /// Degraded ──threshold→ Unhealthy
    /// ```
    ///
    /// Once the failure threshold is reached, the backend becomes
    /// Unhealthy and should not be considered available by health alone.
    pub fn record_failure(&mut self) -> BackendHealth {
        let now = Instant::now();

        self.last_check = Some(now);
        self.last_failure = Some(now);

        // A failure breaks the consecutive recovery sequence.
        self.recoveries = 0;

        self.failures = self.failures.saturating_add(1);

        if self.failures >= self.failure_threshold {
            self.health = BackendHealth::Unhealthy;
        } else {
            self.health = BackendHealth::Degraded;
        }

        self.health
    }

    /// Resets all observations and returns the monitor to Unknown.
    ///
    /// This does not start or stop the backend. Lifecycle management
    /// belongs to BackendManager.
    pub fn reset(&mut self) {
        self.failures = 0;
        self.recoveries = 0;

        self.health = BackendHealth::Unknown;

        self.last_check = None;
        self.last_failure = None;
        self.last_recovery = None;
    }

    /// Explicitly overrides health state.
    ///
    /// Intended for authoritative Engine/native state changes such as
    /// startup validation or an externally detected native failure.
    ///
    /// Counters are reset because retaining old consecutive observations
    /// after an authoritative override would produce misleading state.
    pub fn force_health(
        &mut self,
        health: BackendHealth,
    ) {
        self.health = health;
        self.failures = 0;
        self.recoveries = 0;
    }

    /// Returns the ratio of currently tracked failure observations
    /// against the total tracked success/failure observations.
    ///
    /// This is a diagnostic metric only. It is not used as the primary
    /// health-state transition mechanism.
    pub fn failure_ratio(&self) -> f64 {
        let total = self
            .failures
            .saturating_add(self.recoveries);

        if total == 0 {
            0.0
        } else {
            self.failures as f64 / total as f64
        }
    }

    /// Returns true when the most recent health observation is within
    /// the supplied maximum age.
    pub fn checked_recently(
        &self,
        max_age: Duration,
    ) -> bool {
        match self.last_check {
            Some(last) => last.elapsed() <= max_age,
            None => false,
        }
    }
}

impl Default for HealthMonitor {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_monitor_starts_unknown() {
        let monitor = HealthMonitor::default();

        assert_eq!(
            monitor.health(),
            BackendHealth::Unknown
        );

        assert_eq!(monitor.failures(), 0);
        assert_eq!(monitor.recoveries(), 0);
    }

    #[test]
    fn success_marks_unknown_backend_healthy() {
        let mut monitor =
            HealthMonitor::new(3, 2);

        assert_eq!(
            monitor.record_success(),
            BackendHealth::Healthy
        );

        assert!(monitor.health().is_healthy());
        assert_eq!(monitor.failures(), 0);
        assert_eq!(monitor.recoveries(), 1);
    }

    #[test]
    fn failures_degrade_then_fail() {
        let mut monitor =
            HealthMonitor::new(3, 2);

        assert_eq!(
            monitor.record_failure(),
            BackendHealth::Degraded
        );

        assert_eq!(
            monitor.record_failure(),
            BackendHealth::Degraded
        );

        assert_eq!(
            monitor.record_failure(),
            BackendHealth::Unhealthy
        );

        assert!(monitor.health().is_failed());
        assert_eq!(monitor.failures(), 3);
    }

    #[test]
    fn success_recovers_failed_backend() {
        let mut monitor =
            HealthMonitor::new(2, 2);

        monitor.record_failure();
        monitor.record_failure();

        assert_eq!(
            monitor.health(),
            BackendHealth::Unhealthy
        );

        assert_eq!(
            monitor.record_success(),
            BackendHealth::Degraded
        );

        assert_eq!(
            monitor.record_success(),
            BackendHealth::Healthy
        );
    }

    #[test]
    fn recovery_requires_consecutive_successes() {
        let mut monitor =
            HealthMonitor::new(2, 3);

        monitor.record_failure();
        monitor.record_failure();

        assert_eq!(
            monitor.health(),
            BackendHealth::Unhealthy
        );

        assert_eq!(
            monitor.record_success(),
            BackendHealth::Degraded
        );

        assert_eq!(
            monitor.record_success(),
            BackendHealth::Degraded
        );

        assert_eq!(
            monitor.record_success(),
            BackendHealth::Healthy
        );
    }

    #[test]
    fn success_resets_failure_counter() {
        let mut monitor =
            HealthMonitor::new(3, 2);

        monitor.record_failure();
        monitor.record_failure();

        assert_eq!(monitor.failures(), 2);

        monitor.record_success();

        assert_eq!(monitor.failures(), 0);
    }

    #[test]
    fn failure_resets_recovery_counter() {
        let mut monitor =
            HealthMonitor::new(3, 2);

        monitor.record_success();

        assert_eq!(monitor.recoveries(), 1);

        monitor.record_failure();

        assert_eq!(monitor.recoveries(), 0);
    }

    #[test]
    fn thresholds_are_at_least_one() {
        let monitor =
            HealthMonitor::new(0, 0);

        assert_eq!(
            monitor.failure_threshold(),
            1
        );

        assert_eq!(
            monitor.recovery_threshold(),
            1
        );
    }

    #[test]
    fn reset_restores_unknown() {
        let mut monitor =
            HealthMonitor::new(2, 2);

        monitor.record_failure();
        monitor.record_success();

        monitor.reset();

        assert_eq!(
            monitor.health(),
            BackendHealth::Unknown
        );

        assert_eq!(monitor.failures(), 0);
        assert_eq!(monitor.recoveries(), 0);

        assert!(monitor.last_check().is_none());
        assert!(monitor.last_failure().is_none());
        assert!(monitor.last_recovery().is_none());
    }

    #[test]
    fn force_health_works() {
        let mut monitor =
            HealthMonitor::default();

        monitor.force_health(
            BackendHealth::Healthy
        );

        assert_eq!(
            monitor.health(),
            BackendHealth::Healthy
        );

        monitor.force_health(
            BackendHealth::Unhealthy
        );

        assert!(
            monitor.health().is_failed()
        );

        assert_eq!(monitor.failures(), 0);
        assert_eq!(monitor.recoveries(), 0);
    }

    #[test]
    fn failure_ratio_is_zero_initially() {
        let monitor =
            HealthMonitor::default();

        assert_eq!(
            monitor.failure_ratio(),
            0.0
        );
    }

    #[test]
    fn failure_ratio_is_calculated() {
        let mut monitor =
            HealthMonitor::new(10, 10);

        monitor.record_failure();
        monitor.record_failure();

        monitor.record_success();
        monitor.record_success();

        assert!(
            (monitor.failure_ratio() - 0.5).abs()
                < f64::EPSILON
        );
    }

    #[test]
    fn recent_check_is_detected() {
        let mut monitor =
            HealthMonitor::default();

        assert!(
            !monitor.checked_recently(
                Duration::from_secs(1)
            )
        );

        monitor.record_success();

        assert!(
            monitor.checked_recently(
                Duration::from_secs(1)
            )
        );
    }

    #[test]
    fn health_availability() {
        assert!(
            BackendHealth::Healthy.is_available()
        );

        assert!(
            BackendHealth::Degraded.is_available()
        );

        assert!(
            !BackendHealth::Unhealthy.is_available()
        );

        assert!(
            !BackendHealth::Unknown.is_available()
        );
    }

    #[test]
    fn unknown_success_does_not_require_recovery_threshold() {
        let mut monitor =
            HealthMonitor::new(3, 10);

        assert_eq!(
            monitor.record_success(),
            BackendHealth::Healthy
        );

        assert!(monitor.health().is_healthy());
    }

    #[test]
    fn failure_after_success_starts_new_failure_sequence() {
        let mut monitor =
            HealthMonitor::new(3, 2);

        monitor.record_success();

        assert_eq!(monitor.failures(), 0);

        monitor.record_failure();

        assert_eq!(monitor.failures(), 1);
        assert_eq!(monitor.recoveries(), 0);
        assert_eq!(
            monitor.health(),
            BackendHealth::Degraded
        );
    }

    #[test]
    fn success_after_failure_starts_new_recovery_sequence() {
        let mut monitor =
            HealthMonitor::new(3, 3);

        monitor.record_failure();

        assert_eq!(
            monitor.health(),
            BackendHealth::Degraded
        );

        monitor.record_success();

        assert_eq!(monitor.recoveries(), 1);
        assert_eq!(monitor.failures(), 0);
        assert_eq!(
            monitor.health(),
            BackendHealth::Degraded
        );

        monitor.record_success();
        assert_eq!(
            monitor.health(),
            BackendHealth::Degraded
        );

        monitor.record_success();
        assert_eq!(
            monitor.health(),
            BackendHealth::Healthy
        );
    }
}
