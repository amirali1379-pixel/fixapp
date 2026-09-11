// This module calls the native Windows Filtering Platform API
// (FwpmEngineOpen0 / FwpmEngineClose0) via FFI, which requires `unsafe`.
// Every `unsafe` block below is scoped to a single FFI call with its
// return value checked immediately afterwards.

use network_core::EngineError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfpEngineState { Closed, Opening, Open, Degraded, Closing, Failed }

impl WfpEngineState {
    pub fn is_open(self) -> bool { matches!(self, Self::Open | Self::Degraded) }
    pub fn is_terminal(self) -> bool { matches!(self, Self::Closed | Self::Failed) }
    pub fn can_open(self) -> bool { matches!(self, Self::Closed | Self::Failed) }
    pub fn can_close(self) -> bool { matches!(self, Self::Open | Self::Degraded | Self::Failed) }

    pub fn can_transition_to(self, next: Self) -> bool {
        match (self, next) {
            (Self::Closed, Self::Opening) => true,
            (Self::Opening, Self::Open | Self::Failed | Self::Closing) => true,
            (Self::Open, Self::Degraded | Self::Closing | Self::Failed) => true,
            (Self::Degraded, Self::Open | Self::Closing | Self::Failed) => true,
            (Self::Closing, Self::Closed | Self::Failed) => true,
            (Self::Failed, Self::Opening | Self::Closing) => true,
            (a, b) if a == b => true,
            _ => false,
        }
    }
}

#[derive(Debug)]
pub struct WfpEngine {
    state: WfpEngineState,
    native_handle: Option<usize>,
    sublayer_installed: bool,
}

impl WfpEngine {
    pub fn new() -> Self { Self { state: WfpEngineState::Closed, native_handle: None, sublayer_installed: false } }
    pub fn state(&self) -> WfpEngineState { self.state }
    pub fn is_open(&self) -> bool { self.state.is_open() }
    pub fn native_handle(&self) -> Option<usize> { self.native_handle }
    pub fn sublayer_installed(&self) -> bool { self.sublayer_installed }

    pub fn open(&mut self) -> Result<(), EngineError> {
        if !self.state.can_open() {
            return Err(EngineError::backend(
                network_core::EngineErrorCode::BackendAlreadyRunning,
                "wfp",
            ));
        }
        self.transition(WfpEngineState::Opening)?;

        #[cfg(windows)]
        {
            match open_native_engine() {
                Ok(handle) => {
                    self.native_handle = Some(handle);
                    if let Err(error) = crate::add_sublayer(handle) {
                        let _ = close_native_engine(handle);
                        self.native_handle = None;
                        self.state = WfpEngineState::Failed;
                        return Err(EngineError::with_message(
                            network_core::EngineErrorCode::BackendInitializationFailed,
                            format!("WFP sublayer install failed: {}", error.message()),
                        ));
                    }
                    self.sublayer_installed = true;
                    self.transition(WfpEngineState::Open)?;
                    Ok(())
                }
                Err(error) => {
                    self.native_handle = None;
                    self.sublayer_installed = false;
                    self.state = WfpEngineState::Failed;
                    Err(error)
                }
            }
        }

        #[cfg(not(windows))]
        {
            self.native_handle = None;
            self.sublayer_installed = false;
            self.state = WfpEngineState::Failed;
            Err(EngineError::backend(
                network_core::EngineErrorCode::BackendUnavailable,
                "wfp",
            ))
        }
    }

    pub fn close(&mut self) -> Result<(), EngineError> {
        if self.state == WfpEngineState::Closed {
            return Ok(());
        }
        if !self.state.can_close() {
            return Err(EngineError::backend(
                network_core::EngineErrorCode::InvalidStateTransition,
                "wfp",
            ));
        }
        self.transition(WfpEngineState::Closing)?;

        #[cfg(windows)]
        {
            let handle = self.native_handle.take();
            let mut first_error = None;
            if let Some(handle) = handle {
                if self.sublayer_installed {
                    if let Err(error) = crate::remove_sublayer(handle) {
                        first_error = Some(EngineError::with_message(
                            network_core::EngineErrorCode::BackendShutdownFailed,
                            format!("WFP sublayer removal failed: {}", error.message()),
                        ));
                    }
                    self.sublayer_installed = false;
                }
                if let Err(error) = close_native_engine(handle) {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            } else {
                self.sublayer_installed = false;
            }

            if let Some(error) = first_error {
                self.state = WfpEngineState::Failed;
                return Err(error);
            }
            self.transition(WfpEngineState::Closed)?;
            Ok(())
        }

        #[cfg(not(windows))]
        {
            self.native_handle = None;
            self.sublayer_installed = false;
            self.state = WfpEngineState::Closed;
            Ok(())
        }
    }

    pub fn mark_degraded(&mut self) -> Result<(), EngineError> { self.transition(WfpEngineState::Degraded) }
    pub fn mark_recovered(&mut self) -> Result<(), EngineError> { self.transition(WfpEngineState::Open) }
    pub fn mark_failed(&mut self) { self.native_handle = None; self.sublayer_installed = false; self.state = WfpEngineState::Failed; }

    pub fn require_open(&self) -> Result<usize, EngineError> {
        if !self.state.is_open() {
            return Err(EngineError::backend(
                network_core::EngineErrorCode::BackendNotRunning,
                "wfp",
            ));
        }
        self.native_handle.ok_or_else(|| {
            EngineError::backend(
                network_core::EngineErrorCode::InvalidHandle,
                "wfp",
            )
        })
    }

    fn transition(&mut self, next: WfpEngineState) -> Result<(), EngineError> {
        if !self.state.can_transition_to(next) {
            return Err(EngineError::backend(
                network_core::EngineErrorCode::InvalidStateTransition,
                "wfp",
            ));
        }
        self.state = next;
        Ok(())
    }
}

impl Default for WfpEngine {
    fn default() -> Self { Self::new() }
}

#[cfg(windows)]
fn open_native_engine() -> Result<usize, EngineError> {
    #[link(name = "fwpuclnt")]
    unsafe extern "system" {
        fn FwpmEngineOpen0(
            server_name: *const u16,
            authn_service: u32,
            auth_identity: *const core::ffi::c_void,
            session: *const core::ffi::c_void,
            engine_handle: *mut *mut core::ffi::c_void,
        ) -> u32;
    }

    let mut handle: *mut core::ffi::c_void = core::ptr::null_mut();
    let status = unsafe {
        FwpmEngineOpen0(
            core::ptr::null(),
            0,
            core::ptr::null(),
            core::ptr::null(),
            &mut handle,
        )
    };

    if status != 0 {
        return Err(EngineError::backend_native(
            network_core::EngineErrorCode::BackendInitializationFailed,
            "wfp",
            status as i32,
        ));
    }
    if handle.is_null() {
        return Err(EngineError::backend(
            network_core::EngineErrorCode::InvalidHandle,
            "wfp",
        ));
    }
    Ok(handle as usize)
}

#[cfg(windows)]
fn close_native_engine(handle: usize) -> Result<(), EngineError> {
    #[link(name = "fwpuclnt")]
    unsafe extern "system" {
        fn FwpmEngineClose0(engine_handle: *mut core::ffi::c_void) -> u32;
    }

    if handle == 0 {
        return Err(EngineError::backend(
            network_core::EngineErrorCode::InvalidHandle,
            "wfp",
        ));
    }

    let status = unsafe { FwpmEngineClose0(handle as *mut core::ffi::c_void) };
    if status != 0 {
        return Err(EngineError::backend_native(
            network_core::EngineErrorCode::BackendShutdownFailed,
            "wfp",
            status as i32,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_state_is_closed() {
        let engine = WfpEngine::new();
        assert_eq!(engine.state(), WfpEngineState::Closed);
        assert!(!engine.is_open());
        assert_eq!(engine.native_handle(), None);
        assert!(!engine.sublayer_installed());
    }

    #[test]
    fn valid_transitions() {
        assert!(WfpEngineState::Closed.can_transition_to(WfpEngineState::Opening));
        assert!(WfpEngineState::Opening.can_transition_to(WfpEngineState::Open));
        assert!(WfpEngineState::Open.can_transition_to(WfpEngineState::Closing));
        assert!(WfpEngineState::Closing.can_transition_to(WfpEngineState::Closed));
    }

    #[test]
    fn invalid_transition_is_rejected() {
        assert!(!WfpEngineState::Closed.can_transition_to(WfpEngineState::Open));
        assert!(!WfpEngineState::Opening.can_transition_to(WfpEngineState::Closed));
    }

    #[test]
    fn require_open_fails_when_closed() {
        assert!(WfpEngine::new().require_open().is_err());
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_open_fails_cleanly() {
        let mut engine = WfpEngine::new();
        assert!(engine.open().is_err());
        assert_eq!(engine.state(), WfpEngineState::Failed);
    }
}