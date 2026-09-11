use crate::error::{EngineError, EngineErrorCode};

/// Explicit ownership state for packet lifecycle tracking.
/// Ownership is authoritative for the packet lifecycle; the bus must not
/// duplicate, implicitly release, or reacquire an already released packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OwnershipState {
    Allocated,
    BackendOwned,
    EngineOwned,
    BusOwned,
    ProcessingOwned,
    HostOwned,
    Released,
}

impl OwnershipState {
    pub const fn is_active(self) -> bool { !matches!(self, Self::Released) }
    pub const fn is_transferable(self) -> bool { self.is_active() }
    pub const fn is_engine_owned(self) -> bool { matches!(self, Self::EngineOwned | Self::BusOwned | Self::ProcessingOwned) }
    pub const fn is_backend_owned(self) -> bool { matches!(self, Self::BackendOwned) }
    pub const fn is_bus_owned(self) -> bool { matches!(self, Self::BusOwned) }
    pub const fn is_processing_owned(self) -> bool { matches!(self, Self::ProcessingOwned) }
    pub const fn is_host_owned(self) -> bool { matches!(self, Self::HostOwned) }
    pub const fn is_released(self) -> bool { matches!(self, Self::Released) }
}

pub type OwnershipResult = Result<OwnershipState, EngineError>;

/// Authoritative transition table for one packet.
///
/// Normal path:
/// Allocated → BackendOwned → EngineOwned → BusOwned → ProcessingOwned
/// → HostOwned → Released
///
/// Processing may return to EngineOwned for requeue. Any active state may
/// transition to Released for cleanup. Released is terminal.
pub fn transition_ownership(current: OwnershipState, target: OwnershipState) -> OwnershipResult {
    match (current, target) {
        (current, target) if current == target && current.is_active() => Ok(target),
        (OwnershipState::Allocated, OwnershipState::BackendOwned)
        | (OwnershipState::BackendOwned, OwnershipState::EngineOwned)
        | (OwnershipState::EngineOwned, OwnershipState::BusOwned)
        | (OwnershipState::BusOwned, OwnershipState::ProcessingOwned)
        | (OwnershipState::ProcessingOwned, OwnershipState::HostOwned)
        | (OwnershipState::ProcessingOwned, OwnershipState::EngineOwned)
        | (OwnershipState::HostOwned, OwnershipState::Released) => Ok(target),
        (current, OwnershipState::Released) if current.is_active() => Ok(OwnershipState::Released),
        (OwnershipState::Released, _) => Err(EngineError::with_message(
            EngineErrorCode::InvalidStateTransition,
            "use-after-release: packet has already been released",
        )),
        (current, target) => Err(EngineError::with_message(
            EngineErrorCode::InvalidStateTransition,
            format!("illegal ownership transition: {:?} → {:?}", current, target),
        )),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipTracker {
    state: OwnershipState,
    history: Vec<OwnershipState>,
}

impl OwnershipTracker {
    pub fn new() -> Self { Self { state: OwnershipState::Allocated, history: vec![OwnershipState::Allocated] } }
    pub fn current(&self) -> OwnershipState { self.state }
    pub fn history(&self) -> &[OwnershipState] { &self.history }
    pub fn transition(&mut self, target: OwnershipState) -> OwnershipResult {
        let result = transition_ownership(self.state, target);
        if let Ok(new_state) = result { self.state = new_state; self.history.push(new_state); }
        result
    }
    pub fn is_active(&self) -> bool { self.state.is_active() }
    pub fn is_released(&self) -> bool { self.state.is_released() }
    pub fn is_backend_owned(&self) -> bool { self.state.is_backend_owned() }
    pub fn is_engine_owned(&self) -> bool { self.state.is_engine_owned() }
    pub fn is_bus_owned(&self) -> bool { self.state.is_bus_owned() }
    pub fn is_processing_owned(&self) -> bool { self.state.is_processing_owned() }
    pub fn is_host_owned(&self) -> bool { self.state.is_host_owned() }
    pub fn handoff_backend_to_engine(&mut self) -> OwnershipResult { self.transition(OwnershipState::EngineOwned) }
    pub fn handoff_engine_to_bus(&mut self) -> OwnershipResult { self.transition(OwnershipState::BusOwned) }
    pub fn handoff_bus_to_processing(&mut self) -> OwnershipResult { self.transition(OwnershipState::ProcessingOwned) }
    pub fn requeue_to_engine(&mut self) -> OwnershipResult { self.transition(OwnershipState::EngineOwned) }
    pub fn handoff_to_host(&mut self) -> OwnershipResult { self.transition(OwnershipState::HostOwned) }
    pub fn release(&mut self) -> OwnershipResult { self.transition(OwnershipState::Released) }
}

impl Default for OwnershipTracker { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_states_exist() {
        for state in [OwnershipState::Allocated, OwnershipState::BackendOwned, OwnershipState::EngineOwned, OwnershipState::BusOwned, OwnershipState::ProcessingOwned, OwnershipState::HostOwned, OwnershipState::Released] {
            let _ = state;
        }
    }

    #[test]
    fn legal_capture_processing_lifecycle() {
        let mut t = OwnershipTracker::new();
        t.transition(OwnershipState::BackendOwned).unwrap();
        t.handoff_backend_to_engine().unwrap();
        t.handoff_engine_to_bus().unwrap();
        t.handoff_bus_to_processing().unwrap();
        t.requeue_to_engine().unwrap();
        t.handoff_to_host().unwrap();
        t.release().unwrap();
        assert!(t.is_released());
    }

    #[test]
    fn illegal_direct_transfers_are_rejected() {
        assert!(transition_ownership(OwnershipState::Allocated, OwnershipState::HostOwned).is_err());
        assert!(transition_ownership(OwnershipState::EngineOwned, OwnershipState::ProcessingOwned).is_err());
        assert!(transition_ownership(OwnershipState::BusOwned, OwnershipState::HostOwned).is_err());
    }

    #[test]
    fn released_is_terminal() {
        let mut t = OwnershipTracker::new();
        t.release().unwrap();
        assert!(t.transition(OwnershipState::EngineOwned).is_err());
        assert!(t.transition(OwnershipState::Released).is_err());
    }

    #[test]
    fn emergency_release_is_allowed_from_active_states() {
        for state in [OwnershipState::Allocated, OwnershipState::BackendOwned, OwnershipState::EngineOwned, OwnershipState::BusOwned, OwnershipState::ProcessingOwned, OwnershipState::HostOwned] {
            assert!(transition_ownership(state, OwnershipState::Released).is_ok());
        }
    }

    #[test]
    fn failed_transition_does_not_change_tracker() {
        let mut t = OwnershipTracker::new();
        assert!(t.transition(OwnershipState::HostOwned).is_err());
        assert_eq!(t.current(), OwnershipState::Allocated);
        assert_eq!(t.history(), &[OwnershipState::Allocated]);
    }
}
