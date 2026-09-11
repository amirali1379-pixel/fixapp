#![forbid(unsafe_code)]

use network_core::EngineError;

use crate::capabilities::{BackendCapability, CapabilitySet};

/// Runtime lifecycle of one backend.
///
/// This is the per-backend lifecycle authority.
///
/// Health is intentionally NOT represented here. Backend health is
/// maintained independently by the health subsystem and combined with
/// lifecycle by BackendManager when determining availability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BackendLifecycle {
    Disabled = 0,
    Starting = 1,
    Running = 2,
    Degraded = 3,
    Failed = 4,
    Stopping = 5,
    Stopped = 6,
}

impl BackendLifecycle {
    /// Returns true when the backend is in an operational lifecycle
    /// phase or is currently transitioning.
    pub const fn is_active(self) -> bool {
        matches!(
            self,
            Self::Starting
                | Self::Running
                | Self::Degraded
                | Self::Stopping
        )
    }

    /// Returns true only when the backend is fully running.
    pub const fn is_running(self) -> bool {
        matches!(self, Self::Running)
    }

    /// Returns true when the backend has entered the failed state.
    pub const fn is_failed(self) -> bool {
        matches!(self, Self::Failed)
    }

    /// Returns true when the backend is not expected to perform work.
    ///
    /// `Failed` is deliberately NOT considered terminal because a
    /// failed backend may be restarted.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Stopped | Self::Disabled)
    }

    /// Returns whether a start/restart operation may begin.
    pub const fn can_start(self) -> bool {
        matches!(
            self,
            Self::Disabled
                | Self::Stopped
                | Self::Failed
        )
    }

    /// Returns whether a stop operation may begin.
    pub const fn can_stop(self) -> bool {
        matches!(
            self,
            Self::Starting
                | Self::Running
                | Self::Degraded
        )
    }

    /// Valid lifecycle transition matrix.
    ///
    /// Lifecycle ownership remains here; actual native start/stop
    /// operations remain the responsibility of the backend implementation
    /// and Engine orchestration.
    pub const fn can_transition_to(
        self,
        next: Self,
    ) -> bool {
        if self as u8 == next as u8 {
            return true;
        }

        matches!(
            (self, next),
            // Disabled
            (Self::Disabled, Self::Starting)

                // Starting
                | (Self::Starting, Self::Running)
                | (Self::Starting, Self::Degraded)
                | (Self::Starting, Self::Failed)
                | (Self::Starting, Self::Stopping)

                // Running
                | (Self::Running, Self::Degraded)
                | (Self::Running, Self::Stopping)
                | (Self::Running, Self::Failed)

                // Degraded
                | (Self::Degraded, Self::Running)
                | (Self::Degraded, Self::Stopping)
                | (Self::Degraded, Self::Failed)

                // Stopping
                | (Self::Stopping, Self::Stopped)
                | (Self::Stopping, Self::Failed)

                // Failed
                | (Self::Failed, Self::Starting)
                | (Self::Failed, Self::Stopped)

                // Stopped
                | (Self::Stopped, Self::Starting)
                | (Self::Stopped, Self::Disabled)
        )
    }

    pub fn validate_transition(
        self,
        next: Self,
    ) -> Result<(), EngineError> {
        if self.can_transition_to(next) {
            Ok(())
        } else {
            Err(
                EngineError::invalid_state_transition()
            )
        }
    }
}

/// Metadata describing the role/preference of a backend.
///
/// Role is a selection hint only.
///
/// It does NOT mean:
/// - exclusive ownership of a capability
/// - mandatory activation
/// - automatic startup
/// - traffic ownership
/// - policy authority
///
/// Multiple backends may be Primary for different capability/scope
/// selections, and Primary/Supplementary relationships are ultimately
/// resolved by Engine policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackendRole {
    Primary,
    Supplementary,
}

impl Default for BackendRole {
    fn default() -> Self {
        Self::Supplementary
    }
}

/// Static descriptor for one backend.
///
/// This describes the backend itself and its declared capabilities.
/// Runtime lifecycle and health are stored separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendDescriptor {
    pub name: String,
    pub version: String,
    pub description: String,
    pub capabilities: CapabilitySet,
    pub required: bool,
    pub role: BackendRole,
}

impl BackendDescriptor {
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        description: impl Into<String>,
        capabilities: CapabilitySet,
    ) -> Self {
        Self {
            name: name.into().trim().to_owned(),
            version: version.into().trim().to_owned(),
            description: description.into().trim().to_owned(),
            capabilities,
            required: false,
            role: BackendRole::default(),
        }
    }

    pub fn required(
        mut self,
        required: bool,
    ) -> Self {
        self.required = required;
        self
    }

    pub fn role(
        mut self,
        role: BackendRole,
    ) -> Self {
        self.role = role;
        self
    }

    pub fn primary(self) -> Self {
        self.role(BackendRole::Primary)
    }

    pub fn supports(
        &self,
        capability: BackendCapability,
    ) -> bool {
        self.capabilities.contains(capability)
    }
}

/// Runtime state owned by BackendManager.
///
/// This combines immutable backend descriptor information with mutable
/// lifecycle/error state.
///
/// Health is deliberately not duplicated here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendRuntimeState {
    pub descriptor: BackendDescriptor,
    pub lifecycle: BackendLifecycle,
    pub error_count: u64,
    pub last_native_error: Option<i32>,
}

impl BackendRuntimeState {
    pub fn new(
        descriptor: BackendDescriptor,
    ) -> Self {
        Self {
            descriptor,
            lifecycle: BackendLifecycle::Stopped,
            error_count: 0,
            last_native_error: None,
        }
    }

    /// Performs only lifecycle validation and state mutation.
    ///
    /// This method does NOT start or stop the native backend.
    pub fn transition(
        &mut self,
        next: BackendLifecycle,
    ) -> Result<(), EngineError> {
        self.lifecycle
            .validate_transition(next)?;

        self.lifecycle = next;

        Ok(())
    }

    /// Records a native/backend error.
    ///
    /// Error accounting does not itself decide whether the backend
    /// should be failed or degraded. Health/lifecycle orchestration
    /// makes that decision.
    pub fn record_error(
        &mut self,
        native_error: Option<i32>,
    ) {
        self.error_count =
            self.error_count.saturating_add(1);

        self.last_native_error =
            native_error;
    }

    pub fn clear_errors(&mut self) {
        self.error_count = 0;
        self.last_native_error = None;
    }

    /// Returns true when lifecycle permits normal backend use.
    ///
    /// This is a lifecycle-only check. It does not include health,
    /// native permission, capability scope, resource availability,
    /// or Engine policy.
    pub const fn is_lifecycle_available(&self) -> bool {
        matches!(
            self.lifecycle,
            BackendLifecycle::Running
                | BackendLifecycle::Degraded
        )
    }

    /// Compatibility alias.
    pub const fn is_available(&self) -> bool {
        self.is_lifecycle_available()
    }

    /// Returns whether this backend declares a capability.
    ///
    /// This is a static declaration only. It does not prove that the
    /// capability is currently available at runtime.
    pub fn supports(
        &self,
        capability: BackendCapability,
    ) -> bool {
        self.descriptor
            .supports(capability)
    }

    pub fn capabilities(&self) -> &CapabilitySet {
        &self.descriptor.capabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor() -> BackendDescriptor {
        BackendDescriptor::new(
            "test",
            "1.0.0",
            "test backend",
            CapabilitySet::from([
                BackendCapability::Capture,
                BackendCapability::Inspection,
                BackendCapability::Ipv4,
            ]),
        )
    }

    #[test]
    fn lifecycle_start_transition() {
        let mut state =
            BackendRuntimeState::new(
                descriptor(),
            );

        assert_eq!(
            state.lifecycle,
            BackendLifecycle::Stopped
        );

        state
            .transition(
                BackendLifecycle::Starting,
            )
            .unwrap();

        state
            .transition(
                BackendLifecycle::Running,
            )
            .unwrap();

        assert!(
            state.is_lifecycle_available()
        );
    }

    #[test]
    fn lifecycle_degraded_transition() {
        let mut state =
            BackendRuntimeState::new(
                descriptor(),
            );

        state
            .transition(
                BackendLifecycle::Starting,
            )
            .unwrap();

        state
            .transition(
                BackendLifecycle::Running,
            )
            .unwrap();

        state
            .transition(
                BackendLifecycle::Degraded,
            )
            .unwrap();

        assert!(
            state.is_lifecycle_available()
        );

        assert!(
            !state.lifecycle.is_failed()
        );
    }

    #[test]
    fn failed_is_recoverable() {
        let mut state =
            BackendRuntimeState::new(
                descriptor(),
            );

        state
            .transition(
                BackendLifecycle::Starting,
            )
            .unwrap();

        state
            .transition(
                BackendLifecycle::Failed,
            )
            .unwrap();

        assert!(
            state.lifecycle.can_start()
        );

        state
            .transition(
                BackendLifecycle::Starting,
            )
            .unwrap();

        assert_eq!(
            state.lifecycle,
            BackendLifecycle::Starting
        );
    }

    #[test]
    fn invalid_transition_is_rejected() {
        let mut state =
            BackendRuntimeState::new(
                descriptor(),
            );

        let result = state.transition(
            BackendLifecycle::Stopping,
        );

        assert!(result.is_err());

        assert_eq!(
            state.lifecycle,
            BackendLifecycle::Stopped
        );
    }

    #[test]
    fn stopping_failure_is_allowed() {
        assert!(
            BackendLifecycle::Stopping
                .can_transition_to(
                    BackendLifecycle::Failed,
                )
        );
    }

    #[test]
    fn failed_is_not_terminal() {
        assert!(
            !BackendLifecycle::Failed
                .is_terminal()
        );

        assert!(
            BackendLifecycle::Stopped
                .is_terminal()
        );
    }

    #[test]
    fn capabilities_are_deduplicated() {
        let capabilities =
            CapabilitySet::from([
                BackendCapability::Capture,
                BackendCapability::Capture,
                BackendCapability::Ipv4,
            ]);

        assert_eq!(
            capabilities.len(),
            2
        );

        assert!(
            capabilities.contains(
                BackendCapability::Capture,
            )
        );

        assert!(
            capabilities.contains(
                BackendCapability::Ipv4,
            )
        );
    }

    #[test]
    fn capability_insert_and_remove() {
        let mut capabilities =
            CapabilitySet::new();

        assert!(
            capabilities.insert(
                BackendCapability::Capture,
            )
        );

        assert!(
            capabilities.contains(
                BackendCapability::Capture,
            )
        );

        assert!(
            capabilities.remove(
                BackendCapability::Capture,
            )
        );

        assert!(
            !capabilities.contains(
                BackendCapability::Capture,
            )
        );
    }

    #[test]
    fn descriptor_supports_capability() {
        let descriptor = descriptor();

        assert!(
            descriptor.supports(
                BackendCapability::Capture,
            )
        );

        assert!(
            !descriptor.supports(
                BackendCapability::Reinjection,
            )
        );
    }

    #[test]
    fn runtime_error_tracking() {
        let mut state =
            BackendRuntimeState::new(
                descriptor(),
            );

        state.record_error(Some(123));

        assert_eq!(
            state.error_count,
            1
        );

        assert_eq!(
            state.last_native_error,
            Some(123)
        );

        state.clear_errors();

        assert_eq!(
            state.error_count,
            0
        );

        assert_eq!(
            state.last_native_error,
            None
        );
    }

    #[test]
    fn required_descriptor() {
        let descriptor =
            descriptor().required(true);

        assert!(descriptor.required);
    }

    #[test]
    fn descriptor_defaults_to_supplementary_role() {
        assert_eq!(
            descriptor().role,
            BackendRole::Supplementary
        );
    }

    #[test]
    fn descriptor_can_be_marked_primary() {
        let descriptor =
            descriptor().primary();

        assert_eq!(
            descriptor.role,
            BackendRole::Primary
        );
    }

    #[test]
    fn lifecycle_helpers_are_consistent() {
        assert!(
            BackendLifecycle::Running
                .is_active()
        );

        assert!(
            BackendLifecycle::Running
                .is_running()
        );

        assert!(
            BackendLifecycle::Degraded
                .is_active()
        );

        assert!(
            BackendLifecycle::Failed
                .is_failed()
        );

        assert!(
            BackendLifecycle::Failed
                .can_start()
        );

        assert!(
            BackendLifecycle::Running
                .can_stop()
        );
    }
}