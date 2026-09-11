use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};

use crate::{
    error::{EngineError, EngineErrorCode},
    policy::GatewayPolicy,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineLifecycle {
    Uninitialized = 0,
    Initializing = 1,
    Running = 2,
    ShuttingDown = 3,
    Stopped = 4,
    Failed = 5,
}

impl EngineLifecycle {
    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

#[derive(Debug)]
pub struct EngineState {
    initialized: AtomicBool,
    shutdown_requested: AtomicBool,
    lifecycle: Mutex<EngineLifecycle>,
    gateway_policy: Mutex<Option<GatewayPolicy>>,
}

impl Default for EngineState {
    fn default() -> Self {
        Self::new()
    }
}

impl EngineState {
    pub fn new() -> Self {
        Self {
            initialized: AtomicBool::new(false),
            shutdown_requested: AtomicBool::new(false),
            lifecycle: Mutex::new(EngineLifecycle::Uninitialized),
            gateway_policy: Mutex::new(None),
        }
    }

    pub fn init(&self) -> Result<(), EngineError> {
        let mut lifecycle = self.lifecycle.lock().map_err(|_| {
            EngineError::with_message(
                EngineErrorCode::InternalError,
                "engine lifecycle mutex poisoned",
            )
        })?;

        match *lifecycle {
            EngineLifecycle::Running => {
                return Err(EngineError::already_initialized());
            }

            EngineLifecycle::Initializing
            | EngineLifecycle::ShuttingDown => {
                return Err(EngineError::invalid_state_transition());
            }

            EngineLifecycle::Failed => {
                return Err(EngineError::with_message(
                    EngineErrorCode::InvalidStateTransition,
                    "engine is in failed state",
                ));
            }

            EngineLifecycle::Uninitialized | EngineLifecycle::Stopped => {}
        }

        *lifecycle = EngineLifecycle::Initializing;

        self.shutdown_requested.store(false, Ordering::Release);
        self.initialized.store(true, Ordering::Release);

        *lifecycle = EngineLifecycle::Running;

        Ok(())
    }

    pub fn begin_shutdown(&self) -> Result<(), EngineError> {
        let mut lifecycle = self.lifecycle.lock().map_err(|_| {
            EngineError::with_message(
                EngineErrorCode::InternalError,
                "engine lifecycle mutex poisoned",
            )
        })?;

        match *lifecycle {
            EngineLifecycle::Running => {
                *lifecycle = EngineLifecycle::ShuttingDown;
                self.shutdown_requested.store(true, Ordering::Release);
                Ok(())
            }

            EngineLifecycle::Uninitialized
            | EngineLifecycle::Stopped => Err(EngineError::already_shutdown()),

            EngineLifecycle::Initializing => {
                Err(EngineError::invalid_state_transition())
            }

            EngineLifecycle::ShuttingDown => {
                Err(EngineError::invalid_state_transition())
            }

            EngineLifecycle::Failed => Err(EngineError::with_message(
                EngineErrorCode::InvalidStateTransition,
                "cannot shutdown failed engine",
            )),
        }
    }

    pub fn shutdown(&self) -> Result<(), EngineError> {
        let mut lifecycle = self.lifecycle.lock().map_err(|_| {
            EngineError::with_message(
                EngineErrorCode::InternalError,
                "engine lifecycle mutex poisoned",
            )
        })?;

        match *lifecycle {
            EngineLifecycle::Uninitialized
            | EngineLifecycle::Stopped => {
                return Err(EngineError::already_shutdown());
            }

            EngineLifecycle::Initializing => {
                return Err(EngineError::invalid_state_transition());
            }

            EngineLifecycle::Running => {
                *lifecycle = EngineLifecycle::ShuttingDown;
            }

            EngineLifecycle::ShuttingDown => {}

            EngineLifecycle::Failed => {
                self.initialized.store(false, Ordering::Release);
                self.shutdown_requested.store(true, Ordering::Release);
                *lifecycle = EngineLifecycle::Stopped;
                return Ok(());
            }
        }

        self.shutdown_requested.store(true, Ordering::Release);
        self.initialized.store(false, Ordering::Release);

        if let Ok(mut policy) = self.gateway_policy.lock() {
            *policy = None;
        }

        *lifecycle = EngineLifecycle::Stopped;

        Ok(())
    }

    pub fn mark_failed(&self) {
        self.initialized.store(false, Ordering::Release);
        self.shutdown_requested.store(true, Ordering::Release);

        if let Ok(mut lifecycle) = self.lifecycle.lock() {
            *lifecycle = EngineLifecycle::Failed;
        }
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire)
    }

    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::Acquire)
    }

    pub fn lifecycle(&self) -> EngineLifecycle {
        self.lifecycle
            .lock()
            .map(|state| *state)
            .unwrap_or(EngineLifecycle::Failed)
    }

    pub fn require_running(&self) -> Result<(), EngineError> {
        if !self.is_initialized() {
            return Err(EngineError::not_initialized());
        }

        match self.lifecycle() {
            EngineLifecycle::Running => Ok(()),

            EngineLifecycle::ShuttingDown => {
                Err(EngineError::shutdown_in_progress())
            }

            EngineLifecycle::Stopped | EngineLifecycle::Uninitialized => {
                Err(EngineError::not_initialized())
            }

            EngineLifecycle::Initializing => {
                Err(EngineError::invalid_state_transition())
            }

            EngineLifecycle::Failed => Err(EngineError::with_message(
                EngineErrorCode::InternalError,
                "engine is in failed state",
            )),
        }
    }

    pub fn set_gateway_policy(
        &self,
        policy: GatewayPolicy,
    ) -> Result<(), EngineError> {
        self.require_running()?;

        let mut current = self.gateway_policy.lock().map_err(|_| {
            EngineError::with_message(
                EngineErrorCode::InternalError,
                "gateway policy mutex poisoned",
            )
        })?;

        *current = Some(policy);

        Ok(())
    }

    pub fn gateway_policy(&self) -> Result<Option<GatewayPolicy>, EngineError> {
        let policy = self.gateway_policy.lock().map_err(|_| {
            EngineError::with_message(
                EngineErrorCode::InternalError,
                "gateway policy mutex poisoned",
            )
        })?;

        Ok(policy.clone())
    }

    pub fn clear_gateway_policy(&self) -> Result<(), EngineError> {
        let mut policy = self.gateway_policy.lock().map_err(|_| {
            EngineError::with_message(
                EngineErrorCode::InternalError,
                "gateway policy mutex poisoned",
            )
        })?;

        *policy = None;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_uninitialized() {
        let state = EngineState::new();

        assert!(!state.is_initialized());
        assert_eq!(
            state.lifecycle(),
            EngineLifecycle::Uninitialized
        );
    }

    #[test]
    fn init_transitions_to_running() {
        let state = EngineState::new();

        assert!(state.init().is_ok());
        assert!(state.is_initialized());
        assert_eq!(
            state.lifecycle(),
            EngineLifecycle::Running
        );
    }

    #[test]
    fn double_init_is_rejected() {
        let state = EngineState::new();

        assert!(state.init().is_ok());
        assert!(state.init().is_err());
    }

    #[test]
    fn shutdown_transitions_to_stopped() {
        let state = EngineState::new();

        state.init().unwrap();
        state.shutdown().unwrap();

        assert!(!state.is_initialized());
        assert!(state.is_shutdown_requested());
        assert_eq!(
            state.lifecycle(),
            EngineLifecycle::Stopped
        );
    }

    #[test]
    fn restart_is_allowed() {
        let state = EngineState::new();

        state.init().unwrap();
        state.shutdown().unwrap();

        assert!(state.init().is_ok());
        assert!(state.is_initialized());
        assert!(!state.is_shutdown_requested());
        assert_eq!(
            state.lifecycle(),
            EngineLifecycle::Running
        );
    }

    #[test]
    fn require_running_rejects_uninitialized() {
        let state = EngineState::new();

        assert!(state.require_running().is_err());
    }

    #[test]
    fn require_running_accepts_running() {
        let state = EngineState::new();

        state.init().unwrap();

        assert!(state.require_running().is_ok());
    }

    #[test]
    fn begin_shutdown_is_explicit() {
        let state = EngineState::new();

        state.init().unwrap();
        state.begin_shutdown().unwrap();

        assert!(state.is_shutdown_requested());
        assert_eq!(
            state.lifecycle(),
            EngineLifecycle::ShuttingDown
        );
    }

    #[test]
    fn failed_state_can_be_recovered_by_shutdown() {
        let state = EngineState::new();

        state.init().unwrap();
        state.mark_failed();

        assert_eq!(
            state.lifecycle(),
            EngineLifecycle::Failed
        );

        assert!(state.shutdown().is_ok());

        assert_eq!(
            state.lifecycle(),
            EngineLifecycle::Stopped
        );
    }
}