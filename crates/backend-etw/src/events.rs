use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EtwEventKind {
    PacketObserved,
    FlowStarted,
    FlowUpdated,
    FlowEnded,
    InterfaceChanged,
    RouteChanged,
    NeighborChanged,
    BackendStarted,
    BackendStopped,
    BackendError,
    Diagnostic,
    // Added based on PROJECT_EXECUTION_PLAN.md Section 16
    CaptureStarted,
    CaptureStopped,
    BackendFailover,
    GatewayStateChange,
    PolicyApplied,
    DropRecorded,
    FilterInstalled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtwSeverity {
    Trace,
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

impl EtwSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone)]
pub struct EtwEvent {
    pub event_id: EtwEventId, // Added as per plan
    pub kind: EtwEventKind,
    pub severity: EtwSeverity,
    pub timestamp: u64,
    pub provider: String,
    pub message: String,
}

impl EtwEvent {
    pub fn new(
        event_id: EtwEventId, // Added parameter
        kind: EtwEventKind,
        severity: EtwSeverity,
        timestamp: u64,
        provider: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            event_id,
            kind,
            severity,
            timestamp,
            provider: provider.into(),
            message: message.into(),
        }
    }

    pub fn diagnostic(
        timestamp: u64,
        provider: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::new(
            EtwEventId::DIAGNOSTIC,
            EtwEventKind::Diagnostic,
            EtwSeverity::Info,
            timestamp,
            provider,
            message,
        )
    }

    // Helper constructors for frequently emitted events
    pub fn capture_started(
        timestamp: u64,
        provider: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::new(
            EtwEventId::CAPTURE_STARTED,
            EtwEventKind::CaptureStarted,
            EtwSeverity::Info,
            timestamp,
            provider,
            message,
        )
    }

    pub fn capture_stopped(
        timestamp: u64,
        provider: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::new(
            EtwEventId::CAPTURE_STOPPED,
            EtwEventKind::CaptureStopped,
            EtwSeverity::Info,
            timestamp,
            provider,
            message,
        )
    }

    pub fn backend_failover(
        timestamp: u64,
        provider: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::new(
            EtwEventId::BACKEND_FAILOVER,
            EtwEventKind::BackendFailover,
            EtwSeverity::Warning,
            timestamp,
            provider,
            message,
        )
    }

    pub fn gateway_state_change(
        timestamp: u64,
        provider: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::new(
            EtwEventId::GATEWAY_STATE_CHANGE,
            EtwEventKind::GatewayStateChange,
            EtwSeverity::Info,
            timestamp,
            provider,
            message,
        )
    }

    pub fn policy_applied(
        timestamp: u64,
        provider: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::new(
            EtwEventId::POLICY_APPLIED,
            EtwEventKind::PolicyApplied,
            EtwSeverity::Debug,
            timestamp,
            provider,
            message,
        )
    }

    pub fn drop_recorded(
        timestamp: u64,
        provider: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::new(
            EtwEventId::DROP_RECORDED,
            EtwEventKind::DropRecorded,
            EtwSeverity::Warning,
            timestamp,
            provider,
            message,
        )
    }

    pub fn filter_installed(
        timestamp: u64,
        provider: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::new(
            EtwEventId::FILTER_INSTALLED,
            EtwEventKind::FilterInstalled,
            EtwSeverity::Info,
            timestamp,
            provider,
            message,
        )
    }
}

impl fmt::Display for EtwEvent {
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        write!(
            f,
            "[{}] {}: {}",
            self.severity.as_str(),
            self.provider,
            self.message
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EtwEventId(pub u16);

impl EtwEventId {
    pub const PACKET_OBSERVED: Self = Self(1);
    pub const FLOW_STARTED: Self = Self(2);
    pub const FLOW_UPDATED: Self = Self(3);
    pub const FLOW_ENDED: Self = Self(4);
    pub const INTERFACE_CHANGED: Self = Self(5);
    pub const ROUTE_CHANGED: Self = Self(6);
    pub const NEIGHBOR_CHANGED: Self = Self(7);
    pub const BACKEND_STARTED: Self = Self(8);
    pub const BACKEND_STOPPED: Self = Self(9);
    pub const BACKEND_ERROR: Self = Self(10);
    pub const DIAGNOSTIC: Self = Self(11);
    // Added IDs for new kinds
    pub const CAPTURE_STARTED: Self = Self(12);
    pub const CAPTURE_STOPPED: Self = Self(13);
    pub const BACKEND_FAILOVER: Self = Self(14);
    pub const GATEWAY_STATE_CHANGE: Self = Self(15);
    pub const POLICY_APPLIED: Self = Self(16);
    pub const DROP_RECORDED: Self = Self(17);
    pub const FILTER_INSTALLED: Self = Self(18);

    pub fn for_kind(kind: EtwEventKind) -> Self {
        match kind {
            EtwEventKind::PacketObserved => Self::PACKET_OBSERVED,
            EtwEventKind::FlowStarted => Self::FLOW_STARTED,
            EtwEventKind::FlowUpdated => Self::FLOW_UPDATED,
            EtwEventKind::FlowEnded => Self::FLOW_ENDED,
            EtwEventKind::InterfaceChanged => Self::INTERFACE_CHANGED,
            EtwEventKind::RouteChanged => Self::ROUTE_CHANGED,
            EtwEventKind::NeighborChanged => Self::NEIGHBOR_CHANGED,
            EtwEventKind::BackendStarted => Self::BACKEND_STARTED,
            EtwEventKind::BackendStopped => Self::BACKEND_STOPPED,
            EtwEventKind::BackendError => Self::BACKEND_ERROR,
            EtwEventKind::Diagnostic => Self::DIAGNOSTIC,
            EtwEventKind::CaptureStarted => Self::CAPTURE_STARTED,
            EtwEventKind::CaptureStopped => Self::CAPTURE_STOPPED,
            EtwEventKind::BackendFailover => Self::BACKEND_FAILOVER,
            EtwEventKind::GatewayStateChange => Self::GATEWAY_STATE_CHANGE,
            EtwEventKind::PolicyApplied => Self::POLICY_APPLIED,
            EtwEventKind::DropRecorded => Self::DROP_RECORDED,
            EtwEventKind::FilterInstalled => Self::FILTER_INSTALLED,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_has_stable_names() {
        assert_eq!(
            EtwSeverity::Trace.as_str(),
            "trace"
        );
        assert_eq!(
            EtwSeverity::Info.as_str(),
            "info"
        );
        assert_eq!(
            EtwSeverity::Critical.as_str(),
            "critical"
        );
    }

    #[test]
    fn event_is_created_correctly() {
        // Updated to include event_id
        let event = EtwEvent::new(
            EtwEventId::BACKEND_STARTED,
            EtwEventKind::BackendStarted,
            EtwSeverity::Info,
            100,
            "network-engine",
            "backend started",
        );

        assert_eq!(
            event.kind,
            EtwEventKind::BackendStarted
        );
        assert_eq!(
            event.severity,
            EtwSeverity::Info
        );
        assert_eq!(event.timestamp, 100);
        assert_eq!(
            event.provider,
            "network-engine"
        );
        assert_eq!(
            event.message,
            "backend started"
        );
        assert_eq!(
            event.event_id,
            EtwEventId::BACKEND_STARTED
        );
    }

    #[test]
    fn diagnostic_event_uses_expected_defaults() {
        let event = EtwEvent::diagnostic(
            42,
            "engine",
            "diagnostic message",
        );

        assert_eq!(
            event.kind,
            EtwEventKind::Diagnostic
        );
        assert_eq!(
            event.severity,
            EtwSeverity::Info
        );
        assert_eq!(event.timestamp, 42);
        assert_eq!(
            event.event_id,
            EtwEventId::DIAGNOSTIC
        );
    }

    #[test]
    fn event_display_is_readable() {
        // Updated to include event_id
        let event = EtwEvent::new(
            EtwEventId::BACKEND_ERROR,
            EtwEventKind::BackendError,
            EtwSeverity::Error,
            1,
            "wfp",
            "initialization failed",
        );

        assert_eq!(
            event.to_string(),
            "[error] wfp: initialization failed"
        );
    }

    #[test]
    fn event_ids_are_stable() {
        assert_eq!(
            EtwEventId::for_kind(
                EtwEventKind::PacketObserved
            ),
            EtwEventId::PACKET_OBSERVED
        );

        assert_eq!(
            EtwEventId::for_kind(
                EtwEventKind::BackendError
            ),
            EtwEventId::BACKEND_ERROR
        );
    }
}