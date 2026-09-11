#![forbid(unsafe_code)]

use std::fmt;

use network_core::error::EngineError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FlowState {
    New = 0,
    Active = 1,
    Closed = 2,
    Expired = 3,
}

impl FlowState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Closed | Self::Expired
        )
    }

    pub fn is_active(self) -> bool {
        matches!(
            self,
            Self::New | Self::Active
        )
    }

    pub fn can_transition_to(
        self,
        next: Self,
    ) -> bool {
        match (self, next) {
            (Self::New, Self::New) => true,
            (Self::New, Self::Active) => true,
            (Self::New, Self::Closed) => true,
            (Self::New, Self::Expired) => true,

            (Self::Active, Self::Active) => true,
            (Self::Active, Self::Closed) => true,
            (Self::Active, Self::Expired) => true,

            (Self::Closed, Self::Closed) => true,
            (Self::Expired, Self::Expired) => true,

            _ => false,
        }
    }
}

impl TryFrom<u8> for FlowState {
    type Error = EngineError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::New),
            1 => Ok(Self::Active),
            2 => Ok(Self::Closed),
            3 => Ok(Self::Expired),
            _ => Err(EngineError::invalid_argument()),
        }
    }
}

impl From<FlowState> for u8 {
    fn from(value: FlowState) -> Self {
        value as u8
    }
}

impl fmt::Display for FlowState {
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        let value = match self {
            Self::New => "NEW",
            Self::Active => "ACTIVE",
            Self::Closed => "CLOSED",
            Self::Expired => "EXPIRED",
        };

        f.write_str(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowStateTransition {
    pub from: FlowState,
    pub to: FlowState,
}

impl FlowStateTransition {
    pub fn new(
        from: FlowState,
        to: FlowState,
    ) -> Result<Self, EngineError> {
        if !from.can_transition_to(to) {
            return Err(
                EngineError::invalid_state_transition()
            );
        }

        Ok(Self { from, to })
    }

    pub fn apply(
        &self,
        current: &mut FlowState,
    ) -> Result<(), EngineError> {
        if *current != self.from {
            return Err(
                EngineError::invalid_state_transition()
            );
        }

        *current = self.to;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_can_become_active() {
        assert!(
            FlowState::New
                .can_transition_to(
                    FlowState::Active
                )
        );
    }

    #[test]
    fn active_can_become_closed() {
        assert!(
            FlowState::Active
                .can_transition_to(
                    FlowState::Closed
                )
        );
    }

    #[test]
    fn active_can_become_expired() {
        assert!(
            FlowState::Active
                .can_transition_to(
                    FlowState::Expired
                )
        );
    }

    #[test]
    fn terminal_state_cannot_reopen() {
        assert!(
            !FlowState::Closed
                .can_transition_to(
                    FlowState::Active
                )
        );

        assert!(
            !FlowState::Expired
                .can_transition_to(
                    FlowState::Active
                )
        );
    }

    #[test]
    fn terminal_states_are_terminal() {
        assert!(FlowState::Closed.is_terminal());
        assert!(FlowState::Expired.is_terminal());

        assert!(!FlowState::New.is_terminal());
        assert!(!FlowState::Active.is_terminal());
    }

    #[test]
    fn active_states_are_correct() {
        assert!(FlowState::New.is_active());
        assert!(FlowState::Active.is_active());

        assert!(!FlowState::Closed.is_active());
        assert!(!FlowState::Expired.is_active());
    }

    #[test]
    fn conversion_to_u8() {
        assert_eq!(u8::from(FlowState::New), 0);
        assert_eq!(u8::from(FlowState::Active), 1);
        assert_eq!(u8::from(FlowState::Closed), 2);
        assert_eq!(u8::from(FlowState::Expired), 3);
    }

    #[test]
    fn conversion_from_u8() {
        assert_eq!(
            FlowState::try_from(0).unwrap(),
            FlowState::New
        );

        assert_eq!(
            FlowState::try_from(1).unwrap(),
            FlowState::Active
        );

        assert_eq!(
            FlowState::try_from(2).unwrap(),
            FlowState::Closed
        );

        assert_eq!(
            FlowState::try_from(3).unwrap(),
            FlowState::Expired
        );

        assert!(
            FlowState::try_from(99).is_err()
        );
    }

    #[test]
    fn display_is_stable() {
        assert_eq!(
            FlowState::New.to_string(),
            "NEW"
        );

        assert_eq!(
            FlowState::Active.to_string(),
            "ACTIVE"
        );

        assert_eq!(
            FlowState::Closed.to_string(),
            "CLOSED"
        );

        assert_eq!(
            FlowState::Expired.to_string(),
            "EXPIRED"
        );
    }

    #[test]
    fn creates_valid_transition() {
        let transition =
            FlowStateTransition::new(
                FlowState::New,
                FlowState::Active,
            )
            .unwrap();

        assert_eq!(
            transition.from,
            FlowState::New
        );

        assert_eq!(
            transition.to,
            FlowState::Active
        );
    }

    #[test]
    fn rejects_invalid_transition() {
        let result =
            FlowStateTransition::new(
                FlowState::Closed,
                FlowState::Active,
            );

        assert_eq!(
            result.unwrap_err(),
            EngineError::invalid_state_transition()
        );
    }

    #[test]
    fn applies_transition() {
        let transition =
            FlowStateTransition::new(
                FlowState::New,
                FlowState::Active,
            )
            .unwrap();

        let mut state = FlowState::New;

        transition
            .apply(&mut state)
            .unwrap();

        assert_eq!(
            state,
            FlowState::Active
        );
    }

    #[test]
    fn rejects_transition_from_wrong_current_state() {
        let transition =
            FlowStateTransition::new(
                FlowState::New,
                FlowState::Active,
            )
            .unwrap();

        let mut state = FlowState::Closed;

        assert_eq!(
            transition.apply(&mut state).unwrap_err(),
            EngineError::invalid_state_transition()
        );

        assert_eq!(
            state,
            FlowState::Closed
        );
    }
}