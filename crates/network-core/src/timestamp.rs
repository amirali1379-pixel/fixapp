use std::fmt;
use std::time::{Duration, Instant};

/// High-resolution monotonic timestamp suitable for engine measurement.
///
/// Uses a process-wide monotonic baseline. It is suitable for packet
/// ordering, capture/ingestion latency, flow timing, and queue metrics.
///
/// It is NOT a wall-clock timestamp and must not be persisted as a
/// real-world date/time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp {
    /// Nanoseconds since the process-wide monotonic baseline.
    nanos: u64,
}

impl Timestamp {
    /// Creates a timestamp from raw nanoseconds.
    pub const fn from_nanos(nanos: u64) -> Self {
        Self { nanos }
    }

    /// Returns the timestamp as nanoseconds.
    pub const fn as_nanos(&self) -> u64 {
        self.nanos
    }

    /// Returns the timestamp as microseconds.
    pub const fn as_micros(&self) -> u64 {
        self.nanos / 1_000
    }

    /// Returns the timestamp as milliseconds.
    pub const fn as_millis(&self) -> u64 {
        self.nanos / 1_000_000
    }

    /// Calculates the duration from `other` to this timestamp.
    ///
    /// Returns `None` when `other` is later than `self`.
    pub fn duration_since(&self, other: Timestamp) -> Option<Duration> {
        self.nanos
            .checked_sub(other.nanos)
            .map(Duration::from_nanos)
    }

    /// Returns the elapsed duration between two timestamps.
    pub fn elapsed_since(&self, earlier: Timestamp) -> Option<TimeDelta> {
        self.duration_since(earlier).map(TimeDelta::from)
    }

    /// Returns a process-local monotonic timestamp.
    ///
    /// This is the timestamp that capture backends should use when
    /// the native backend does not provide a compatible monotonic
    /// timestamp.
    pub fn now() -> Self {
        static BASELINE: std::sync::OnceLock<Instant> =
            std::sync::OnceLock::new();

        let baseline = BASELINE.get_or_init(Instant::now);
        let elapsed = baseline.elapsed();

        // Instant::elapsed() is practically bounded by process lifetime.
        // Saturating conversion prevents a theoretical platform overflow.
        let nanos = elapsed.as_nanos().min(u64::MAX as u128) as u64;

        Self::from_nanos(nanos)
    }

    /// Returns the zero timestamp.
    pub const fn zero() -> Self {
        Self { nanos: 0 }
    }

    /// Returns true if this timestamp is zero.
    pub const fn is_zero(&self) -> bool {
        self.nanos == 0
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let micros = self.as_micros();
        let millis = micros / 1_000;
        let rem_micros = micros % 1_000;

        write!(f, "{}.{:03}ms", millis, rem_micros)
    }
}

impl Default for Timestamp {
    fn default() -> Self {
        Self::zero()
    }
}

impl std::ops::Add<Duration> for Timestamp {
    type Output = Self;

    fn add(self, rhs: Duration) -> Self::Output {
        let rhs_nanos = rhs.as_nanos().min(u64::MAX as u128) as u64;

        Self::from_nanos(
            self.nanos.saturating_add(rhs_nanos),
        )
    }
}

impl std::ops::Sub<Duration> for Timestamp {
    type Output = Self;

    fn sub(self, rhs: Duration) -> Self::Output {
        let rhs_nanos = rhs.as_nanos().min(u64::MAX as u128) as u64;

        Self::from_nanos(
            self.nanos.saturating_sub(rhs_nanos),
        )
    }
}

/// A duration measured in engine time units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimeDelta {
    nanos: u64,
}

impl TimeDelta {
    pub const fn from_nanos(nanos: u64) -> Self {
        Self { nanos }
    }

    pub const fn from_micros(micros: u64) -> Self {
        Self {
            nanos: micros.saturating_mul(1_000),
        }
    }

    pub const fn from_millis(millis: u64) -> Self {
        Self {
            nanos: millis.saturating_mul(1_000_000),
        }
    }

    pub const fn from_secs(secs: u64) -> Self {
        Self {
            nanos: secs.saturating_mul(1_000_000_000),
        }
    }

    pub const fn as_nanos(&self) -> u64 {
        self.nanos
    }

    pub const fn as_micros(&self) -> u64 {
        self.nanos / 1_000
    }

    pub const fn as_millis(&self) -> u64 {
        self.nanos / 1_000_000
    }

    pub const fn as_secs(&self) -> u64 {
        self.nanos / 1_000_000_000
    }

    pub const fn is_zero(&self) -> bool {
        self.nanos == 0
    }
}

impl From<Duration> for TimeDelta {
    fn from(d: Duration) -> Self {
        let nanos = d.as_nanos().min(u64::MAX as u128) as u64;
        Self::from_nanos(nanos)
    }
}

impl From<TimeDelta> for Duration {
    fn from(d: TimeDelta) -> Self {
        Duration::from_nanos(d.nanos)
    }
}

impl fmt::Display for TimeDelta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = self.as_secs();
        let millis = (self.nanos % 1_000_000_000) / 1_000_000;
        let micros = (self.nanos % 1_000_000) / 1_000;

        if secs > 0 {
            write!(f, "{}.{:03}s", secs, millis)
        } else if millis > 0 {
            write!(f, "{}.{:03}ms", millis, micros)
        } else {
            write!(f, "{}us", self.as_micros())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn timestamp_is_monotonic() {
        let t1 = Timestamp::now();

        thread::sleep(Duration::from_millis(1));

        let t2 = Timestamp::now();

        assert!(t2 > t1);
    }

    #[test]
    fn duration_since_works() {
        let t1 = Timestamp::from_nanos(1_000_000);
        let t2 = Timestamp::from_nanos(5_000_000);

        let delta = t2.duration_since(t1).unwrap();

        assert_eq!(delta, Duration::from_micros(4_000));
    }

    #[test]
    fn elapsed_since_works() {
        let t1 = Timestamp::from_nanos(1_000_000);
        let t2 = Timestamp::from_nanos(3_500_000);

        let delta = t2.elapsed_since(t1).unwrap();

        assert_eq!(delta.as_micros(), 2_500);
    }

    #[test]
    fn duration_since_none_on_reverse() {
        let t1 = Timestamp::from_nanos(5_000_000);
        let t2 = Timestamp::from_nanos(1_000_000);

        assert!(t2.duration_since(t1).is_none());
    }

    #[test]
    fn timestamp_display() {
        let t = Timestamp::from_nanos(1_234_567_890);
        let s = t.to_string();

        assert!(s.contains("1234"));
    }

    #[test]
    fn time_delta_conversions() {
        let d = TimeDelta::from_secs(1);

        assert_eq!(d.as_millis(), 1_000);
        assert_eq!(d.as_micros(), 1_000_000);
        assert_eq!(d.as_nanos(), 1_000_000_000);
    }

    #[test]
    fn time_delta_display() {
        assert_eq!(
            TimeDelta::from_secs(2).to_string(),
            "2.000s"
        );

        assert_eq!(
            TimeDelta::from_millis(500).to_string(),
            "500.000ms"
        );

        assert_eq!(
            TimeDelta::from_micros(100).to_string(),
            "100us"
        );
    }

    #[test]
    fn timestamp_add_duration() {
        let t = Timestamp::from_nanos(1_000_000);
        let t2 = t + Duration::from_micros(500);

        assert_eq!(t2.as_nanos(), 1_500_000);
    }

    #[test]
    fn timestamp_sub_duration() {
        let t = Timestamp::from_nanos(1_000_000);
        let t2 = t - Duration::from_micros(500);

        assert_eq!(t2.as_nanos(), 500_000);
    }

    #[test]
    fn timestamp_sub_saturates() {
        let t = Timestamp::from_nanos(100);
        let t2 = t - Duration::from_micros(500);

        assert_eq!(t2.as_nanos(), 0);
    }

    #[test]
    fn zero_timestamp_is_zero() {
        let t = Timestamp::zero();

        assert!(t.is_zero());
        assert_eq!(t.as_nanos(), 0);
    }

    #[test]
    fn time_delta_zero_is_zero() {
        let d = TimeDelta::from_nanos(0);

        assert!(d.is_zero());
        assert_eq!(d.as_nanos(), 0);
    }

    #[test]
    fn timestamp_ordering_works() {
        let t1 = Timestamp::from_nanos(100);
        let t2 = Timestamp::from_nanos(200);

        assert!(t2 > t1);
        assert!(t1 < t2);
        assert_eq!(t1, Timestamp::from_nanos(100));
    }
}