#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayState {
    Idle,
    Active,
    Degraded,
    Error,
}

impl GatewayState {
    pub fn can_transition_to(self, next: GatewayState) -> bool {
        use GatewayState::*;

        matches!(
            (self, next),
            (Idle, Active)
                | (Idle, Error)
                | (Active, Idle)
                | (Active, Degraded)
                | (Active, Error)
                | (Degraded, Active)
                | (Degraded, Idle)
                | (Degraded, Error)
                | (Error, Idle)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayStateError {
    InvalidTransition {
        from: GatewayState,
        to: GatewayState,
    },
}

#[derive(Debug)]
pub struct GatewayStateManager {
    state: GatewayState,
}

impl GatewayStateManager {
    pub fn new() -> Self {
        Self {
            state: GatewayState::Idle,
        }
    }

    pub fn current(&self) -> GatewayState {
        self.state
    }

    pub fn transition(
        &mut self,
        next: GatewayState,
    ) -> Result<(), GatewayStateError> {
        if self.state == next {
            return Ok(());
        }

        if !self.state.can_transition_to(next) {
            return Err(GatewayStateError::InvalidTransition {
                from: self.state,
                to: next,
            });
        }

        self.state = next;
        Ok(())
    }

    pub fn activate(&mut self) -> Result<(), GatewayStateError> {
        self.transition(GatewayState::Active)
    }

    pub fn degrade(&mut self) -> Result<(), GatewayStateError> {
        self.transition(GatewayState::Degraded)
    }

    pub fn fail(&mut self) -> Result<(), GatewayStateError> {
        self.transition(GatewayState::Error)
    }

    pub fn reset(&mut self) -> Result<(), GatewayStateError> {
        self.transition(GatewayState::Idle)
    }

    /// Explicit administrative state replacement.
    ///
    /// This should only be used by controlled lifecycle code.
    pub(crate) fn force_set(&mut self, state: GatewayState) {
        self.state = state;
    }
}

impl Default for GatewayStateManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_state_is_idle() {
        let manager = GatewayStateManager::new();
        assert_eq!(manager.current(), GatewayState::Idle);
    }

    #[test]
    fn valid_transition_idle_to_active() {
        let mut manager = GatewayStateManager::new();

        assert!(manager.activate().is_ok());
        assert_eq!(manager.current(), GatewayState::Active);
    }

    #[test]
    fn valid_degraded_transition() {
        let mut manager = GatewayStateManager::new();

        manager.activate().unwrap();
        manager.degrade().unwrap();

        assert_eq!(manager.current(), GatewayState::Degraded);
    }

    #[test]
    fn invalid_transition_is_rejected() {
        let mut manager = GatewayStateManager::new();

        let result = manager.degrade();

        assert!(matches!(
            result,
            Err(GatewayStateError::InvalidTransition {
                from: GatewayState::Idle,
                to: GatewayState::Degraded
            })
        ));

        assert_eq!(manager.current(), GatewayState::Idle);
    }

    #[test]
    fn error_can_reset_to_idle() {
        let mut manager = GatewayStateManager::new();

        manager.fail().unwrap();
        assert_eq!(manager.current(), GatewayState::Error);

        manager.reset().unwrap();
        assert_eq!(manager.current(), GatewayState::Idle);
    }
}