#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackpressureLevel {
    Normal,
    Elevated,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackpressureAction {
    Accept,
    Throttle,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackpressureConfig {
    pub elevated_watermark_percent: u8,
    pub critical_watermark_percent: u8,
}

impl Default for BackpressureConfig {
    fn default() -> Self {
        Self {
            elevated_watermark_percent: 75,
            critical_watermark_percent: 95,
        }
    }
}

impl BackpressureConfig {
    pub fn validate(&self) -> bool {
        self.elevated_watermark_percent > 0
            && self.elevated_watermark_percent < 100
            && self.critical_watermark_percent > 0
            && self.critical_watermark_percent <= 100
            && self.elevated_watermark_percent
                < self.critical_watermark_percent
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackpressureDecision {
    pub level: BackpressureLevel,
    pub action: BackpressureAction,
    pub occupancy: usize,
    pub capacity: usize,
}

impl BackpressureDecision {
    pub fn accepts_input(&self) -> bool {
        matches!(
            self.action,
            BackpressureAction::Accept | BackpressureAction::Throttle
        )
    }

    pub fn rejects_input(&self) -> bool {
        matches!(self.action, BackpressureAction::Reject)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BackpressureController {
    config: BackpressureConfig,
}

impl Default for BackpressureController {
    fn default() -> Self {
        Self::new(BackpressureConfig::default())
    }
}

impl BackpressureController {
    pub fn new(config: BackpressureConfig) -> Self {
        let config = if config.validate() {
            config
        } else {
            BackpressureConfig::default()
        };

        Self { config }
    }

    pub fn config(&self) -> BackpressureConfig {
        self.config
    }

    pub fn evaluate(
        &self,
        occupancy: usize,
        capacity: usize,
    ) -> BackpressureDecision {
        if capacity == 0 {
            return BackpressureDecision {
                level: BackpressureLevel::Critical,
                action: BackpressureAction::Reject,
                occupancy,
                capacity,
            };
        }

        let occupancy = occupancy.min(capacity);

        let percent = occupancy
            .saturating_mul(100)
            .checked_div(capacity)
            .unwrap_or(100);

        if percent >= self.config.critical_watermark_percent as usize {
            BackpressureDecision {
                level: BackpressureLevel::Critical,
                action: BackpressureAction::Reject,
                occupancy,
                capacity,
            }
        } else if percent >= self.config.elevated_watermark_percent as usize {
            BackpressureDecision {
                level: BackpressureLevel::Elevated,
                action: BackpressureAction::Throttle,
                occupancy,
                capacity,
            }
        } else {
            BackpressureDecision {
                level: BackpressureLevel::Normal,
                action: BackpressureAction::Accept,
                occupancy,
                capacity,
            }
        }
    }

    pub fn should_accept(
        &self,
        occupancy: usize,
        capacity: usize,
    ) -> bool {
        self.evaluate(occupancy, capacity).accepts_input()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        assert!(BackpressureConfig::default().validate());
    }

    #[test]
    fn normal_queue_accepts() {
        let controller = BackpressureController::default();

        let decision = controller.evaluate(100, 1000);

        assert_eq!(
            decision.level,
            BackpressureLevel::Normal
        );

        assert_eq!(
            decision.action,
            BackpressureAction::Accept
        );

        assert!(decision.accepts_input());
    }

    #[test]
    fn elevated_queue_throttles() {
        let controller = BackpressureController::default();

        let decision = controller.evaluate(800, 1000);

        assert_eq!(
            decision.level,
            BackpressureLevel::Elevated
        );

        assert_eq!(
            decision.action,
            BackpressureAction::Throttle
        );

        assert!(decision.accepts_input());
    }

    #[test]
    fn critical_queue_rejects() {
        let controller = BackpressureController::default();

        let decision = controller.evaluate(960, 1000);

        assert_eq!(
            decision.level,
            BackpressureLevel::Critical
        );

        assert_eq!(
            decision.action,
            BackpressureAction::Reject
        );

        assert!(decision.rejects_input());
        assert!(!decision.accepts_input());
    }

    #[test]
    fn full_queue_is_rejected() {
        let controller = BackpressureController::default();

        let decision = controller.evaluate(1000, 1000);

        assert_eq!(
            decision.action,
            BackpressureAction::Reject
        );
    }

    #[test]
    fn zero_capacity_is_rejected() {
        let controller = BackpressureController::default();

        let decision = controller.evaluate(0, 0);

        assert_eq!(
            decision.level,
            BackpressureLevel::Critical
        );

        assert_eq!(
            decision.action,
            BackpressureAction::Reject
        );
    }

    #[test]
    fn occupancy_is_clamped_to_capacity() {
        let controller = BackpressureController::default();

        let decision = controller.evaluate(5000, 1000);

        assert_eq!(decision.occupancy, 1000);
        assert_eq!(decision.capacity, 1000);
        assert_eq!(
            decision.action,
            BackpressureAction::Reject
        );
    }

    #[test]
    fn invalid_config_falls_back_to_default() {
        let config = BackpressureConfig {
            elevated_watermark_percent: 95,
            critical_watermark_percent: 50,
        };

        let controller = BackpressureController::new(config);

        assert_eq!(
            controller.config(),
            BackpressureConfig::default()
        );
    }

    #[test]
    fn exact_elevated_boundary() {
        let controller = BackpressureController::default();

        let decision = controller.evaluate(750, 1000);

        assert_eq!(
            decision.level,
            BackpressureLevel::Elevated
        );
    }

    #[test]
    fn exact_critical_boundary() {
        let controller = BackpressureController::default();

        let decision = controller.evaluate(950, 1000);

        assert_eq!(
            decision.level,
            BackpressureLevel::Critical
        );
    }
}