use std::fmt;

/// Stable engine error codes.
///
/// These values are part of the internal error contract and can be
/// mapped 1:1 to the public C ABI by the FFI layer.
///
/// Native-specific errors are normalized by backend crates before
/// reaching Engine-level contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum EngineErrorCode {
    Ok = 0,
    Unknown = -1,

    InvalidArgument = 1,
    NullPointer = 2,
    BufferTooSmall = 3,
    IntegerOverflow = 4,

    InvalidHandle = 10,
    HandleReleased = 11,
    HandleTypeMismatch = 12,

    NotInitialized = 20,
    AlreadyInitialized = 21,
    ShutdownInProgress = 22,
    AlreadyShutdown = 23,
    InvalidStateTransition = 24,
    Shutdown = 25,

    BackendUnavailable = 30,
    BackendNotFound = 31,
    BackendAlreadyRegistered = 32,
    BackendAlreadyRunning = 33,
    BackendNotRunning = 34,
    BackendStartFailed = 35,
    BackendStopFailed = 36,
    BackendInitializationFailed = 37,
    BackendShutdownFailed = 38,
    BackendDegraded = 39,
    BackendInitFailed = 40,

    CapabilityUnavailable = 50,
    CapabilityNotSupported = 51,
    CapabilityLost = 52,

    QueueEmpty = 60,
    QueueFull = 61,
    BufferExhausted = 62,
    Backpressure = 63,

    PacketMalformed = 70,
    PacketTooShort = 71,
    PacketUnsupported = 72,
    PacketReleased = 73,
    ParseError = 74,

    ActionNotSupported = 80,
    ActionFailed = 81,
    PassFailed = 82,
    DropFailed = 83,
    ModifyFailed = 84,
    ReinjectionFailed = 85,

    RouteNotFound = 90,
    RouteFailure = 91,
    NeighborUnresolved = 92,
    NeighborFailure = 93,
    NatStateMissing = 94,
    ForwardingFailed = 95,
    GatewayNotReady = 96,
    GatewayConfigurationInvalid = 97,

    ConfigurationInvalid = 100,
    ConfigurationUnsupported = 101,

    ResourceExhausted = 110,
    OperationTimeout = 111,
    ConcurrentOperation = 112,

    InternalError = 200,
}

impl EngineErrorCode {
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    pub const fn is_success(self) -> bool {
        matches!(self, Self::Ok)
    }

    pub const fn is_backend_error(self) -> bool {
        matches!(
            self,
            Self::BackendUnavailable
                | Self::BackendNotFound
                | Self::BackendAlreadyRegistered
                | Self::BackendAlreadyRunning
                | Self::BackendNotRunning
                | Self::BackendStartFailed
                | Self::BackendStopFailed
                | Self::BackendInitializationFailed
                | Self::BackendShutdownFailed
                | Self::BackendDegraded
                | Self::BackendInitFailed
        )
    }

    pub const fn is_recoverable(self) -> bool {
        matches!(
            self,
            Self::QueueEmpty
                | Self::QueueFull
                | Self::BufferExhausted
                | Self::Backpressure
                | Self::BackendUnavailable
                | Self::BackendDegraded
                | Self::CapabilityUnavailable
                | Self::CapabilityLost
                | Self::OperationTimeout
                | Self::ConcurrentOperation
        )
    }

    pub const fn message(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Unknown => "Unknown error",

            Self::InvalidArgument => "Invalid argument",
            Self::NullPointer => "Null pointer",
            Self::BufferTooSmall => "Buffer too small",
            Self::IntegerOverflow => "Integer overflow",

            Self::InvalidHandle => "Invalid handle",
            Self::HandleReleased => "Handle has been released",
            Self::HandleTypeMismatch => "Handle type mismatch",

            Self::NotInitialized => "Engine is not initialized",
            Self::AlreadyInitialized => "Engine is already initialized",
            Self::ShutdownInProgress => "Engine shutdown is in progress",
            Self::AlreadyShutdown => "Engine is already shut down",
            Self::InvalidStateTransition => "Invalid state transition",
            Self::Shutdown => "Engine is shut down",

            Self::BackendUnavailable => "Backend is unavailable",
            Self::BackendNotFound => "Backend not found",
            Self::BackendAlreadyRegistered => "Backend already registered",
            Self::BackendAlreadyRunning => "Backend is already running",
            Self::BackendNotRunning => "Backend is not running",
            Self::BackendStartFailed => "Backend start failed",
            Self::BackendStopFailed => "Backend stop failed",
            Self::BackendInitializationFailed => "Backend initialization failed",
            Self::BackendShutdownFailed => "Backend shutdown failed",
            Self::BackendDegraded => "Backend is degraded",
            Self::BackendInitFailed => "Backend init failed",

            Self::CapabilityUnavailable => "Capability is unavailable",
            Self::CapabilityNotSupported => "Capability is not supported",
            Self::CapabilityLost => "Capability has been lost",

            Self::QueueEmpty => "Queue is empty",
            Self::QueueFull => "Queue is full",
            Self::BufferExhausted => "Buffer resources exhausted",
            Self::Backpressure => "Backpressure is active",

            Self::PacketMalformed => "Malformed packet",
            Self::PacketTooShort => "Packet is too short",
            Self::PacketUnsupported => "Packet type is unsupported",
            Self::PacketReleased => "Packet has already been released",
            Self::ParseError => "Packet parse error",

            Self::ActionNotSupported => "Packet action is not supported",
            Self::ActionFailed => "Packet action failed",
            Self::PassFailed => "Packet pass failed",
            Self::DropFailed => "Packet drop failed",
            Self::ModifyFailed => "Packet modification failed",
            Self::ReinjectionFailed => "Packet reinjection failed",

            Self::RouteNotFound => "Route not found",
            Self::RouteFailure => "Route lookup failed",
            Self::NeighborUnresolved => "Neighbor could not be resolved",
            Self::NeighborFailure => "Neighbor operation failed",
            Self::NatStateMissing => "NAT state is missing",
            Self::ForwardingFailed => "Packet forwarding failed",
            Self::GatewayNotReady => "Gateway is not ready",
            Self::GatewayConfigurationInvalid => {
                "Gateway configuration is invalid"
            }

            Self::ConfigurationInvalid => "Configuration is invalid",
            Self::ConfigurationUnsupported => {
                "Configuration is unsupported"
            }

            Self::ResourceExhausted => "Engine resource exhausted",
            Self::OperationTimeout => "Operation timed out",
            Self::ConcurrentOperation => {
                "Operation conflicts with another operation"
            }

            Self::InternalError => "Internal engine error",
        }
    }
}

/// Convenience alias for engine operations that can fail with an
/// [`EngineError`].
pub type EngineResult<T> = Result<T, EngineError>;

/// Main Engine error type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineError {
    Code(EngineErrorCode),

    Backend {
        code: EngineErrorCode,
        backend: String,
        native_code: Option<i32>,
    },

    Native {
        code: EngineErrorCode,
        native_code: i32,
    },

    Message {
        code: EngineErrorCode,
        message: String,
    },
}

impl EngineError {
    pub const fn code(&self) -> EngineErrorCode {
        match self {
            Self::Code(code) => *code,
            Self::Backend { code, .. } => *code,
            Self::Native { code, .. } => *code,
            Self::Message { code, .. } => *code,
        }
    }

    pub const fn as_i32(&self) -> i32 {
        self.code().as_i32()
    }

    pub fn message(&self) -> String {
        match self {
            Self::Code(code) => code.message().to_owned(),
            Self::Backend {
                code,
                backend,
                native_code,
            } => match native_code {
                Some(native) => {
                    format!(
                        "{}: {} (native error {})",
                        backend,
                        code.message(),
                        native
                    )
                }
                None => {
                    format!("{}: {}", backend, code.message())
                }
            },
            Self::Native {
                code,
                native_code,
            } => {
                format!(
                    "{} (native error {})",
                    code.message(),
                    native_code
                )
            }
            Self::Message { message, .. } => message.clone(),
        }
    }

    pub const fn is_recoverable(&self) -> bool {
        self.code().is_recoverable()
    }

    pub const fn is_backend_error(&self) -> bool {
        self.code().is_backend_error()
    }

    pub fn backend(
        code: EngineErrorCode,
        backend: impl Into<String>,
    ) -> Self {
        Self::Backend {
            code,
            backend: backend.into(),
            native_code: None,
        }
    }

    pub fn backend_native(
        code: EngineErrorCode,
        backend: impl Into<String>,
        native_code: i32,
    ) -> Self {
        Self::Backend {
            code,
            backend: backend.into(),
            native_code: Some(native_code),
        }
    }

    pub fn native(code: EngineErrorCode, native_code: i32) -> Self {
        Self::Native {
            code,
            native_code,
        }
    }

    pub fn with_message(
        code: EngineErrorCode,
        message: impl Into<String>,
    ) -> Self {
        Self::Message {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl std::error::Error for EngineError {}

macro_rules! simple_errors {
    (
        $(
            $name:ident => $code:ident
        ),* $(,)?
    ) => {
        $(
            impl EngineError {
                pub fn $name() -> Self {
                    Self::Code(EngineErrorCode::$code)
                }
            }
        )*
    };
}

simple_errors! {
    invalid_argument => InvalidArgument,
    null_pointer => NullPointer,
    buffer_too_small => BufferTooSmall,
    integer_overflow => IntegerOverflow,

    invalid_handle => InvalidHandle,
    handle_released => HandleReleased,
    handle_type_mismatch => HandleTypeMismatch,

    not_initialized => NotInitialized,
    already_initialized => AlreadyInitialized,
    shutdown_in_progress => ShutdownInProgress,
    already_shutdown => AlreadyShutdown,
    invalid_state_transition => InvalidStateTransition,
    shutdown => Shutdown,

    backend_unavailable => BackendUnavailable,
    backend_not_found => BackendNotFound,
    backend_already_registered => BackendAlreadyRegistered,
    backend_already_running => BackendAlreadyRunning,
    backend_not_running => BackendNotRunning,
    backend_start_failed => BackendStartFailed,
    backend_stop_failed => BackendStopFailed,
    backend_initialization_failed => BackendInitializationFailed,
    backend_shutdown_failed => BackendShutdownFailed,
    backend_degraded => BackendDegraded,
    backend_init_failed => BackendInitFailed,

    capability_unavailable => CapabilityUnavailable,
    capability_not_supported => CapabilityNotSupported,
    capability_lost => CapabilityLost,

    queue_empty => QueueEmpty,
    queue_full => QueueFull,
    buffer_exhausted => BufferExhausted,
    backpressure => Backpressure,

    packet_malformed => PacketMalformed,
    packet_too_short => PacketTooShort,
    packet_unsupported => PacketUnsupported,
    packet_released => PacketReleased,
    parse_error => ParseError,

    action_not_supported => ActionNotSupported,
    action_failed => ActionFailed,
    pass_failed => PassFailed,
    drop_failed => DropFailed,
    modify_failed => ModifyFailed,
    reinjection_failed => ReinjectionFailed,

    route_not_found => RouteNotFound,
    route_failure => RouteFailure,
    neighbor_unresolved => NeighborUnresolved,
    neighbor_failure => NeighborFailure,
    nat_state_missing => NatStateMissing,
    forwarding_failed => ForwardingFailed,
    gateway_not_ready => GatewayNotReady,
    gateway_configuration_invalid => GatewayConfigurationInvalid,

    configuration_invalid => ConfigurationInvalid,
    configuration_unsupported => ConfigurationUnsupported,

    resource_exhausted => ResourceExhausted,
    operation_timeout => OperationTimeout,
    concurrent_operation => ConcurrentOperation,

    internal_error => InternalError,
}

impl From<EngineErrorCode> for EngineError {
    fn from(code: EngineErrorCode) -> Self {
        Self::Code(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(EngineErrorCode::Ok.as_i32(), 0);
        assert_eq!(EngineErrorCode::InvalidArgument.as_i32(), 1);
        assert_eq!(EngineErrorCode::InvalidHandle.as_i32(), 10);
        assert_eq!(EngineErrorCode::BackendUnavailable.as_i32(), 30);
        assert_eq!(EngineErrorCode::CapabilityUnavailable.as_i32(), 50);
        assert_eq!(EngineErrorCode::PacketMalformed.as_i32(), 70);
        assert_eq!(EngineErrorCode::InternalError.as_i32(), 200);
    }

    #[test]
    fn required_errors_exist() {
        // TASK-0007 required errors
        let _ = EngineError::invalid_argument();
        let _ = EngineError::invalid_handle();
        let _ = EngineError::backend_unavailable();
        let _ = EngineError::backend_init_failed();
        let _ = EngineError::capability_unavailable();
        let _ = EngineError::capability_lost();
        let _ = EngineError::action_failed();
        let _ = EngineError::queue_full();
        let _ = EngineError::buffer_exhausted();
        let _ = EngineError::parse_error();
        let _ = EngineError::route_failure();
        let _ = EngineError::neighbor_failure();
        let _ = EngineError::nat_state_missing();
        let _ = EngineError::gateway_not_ready();
        let _ = EngineError::shutdown();
    }

    #[test]
    fn messages_are_non_empty() {
        let codes = [
            EngineErrorCode::InvalidArgument,
            EngineErrorCode::InvalidHandle,
            EngineErrorCode::BackendUnavailable,
            EngineErrorCode::QueueFull,
            EngineErrorCode::PacketMalformed,
            EngineErrorCode::RouteNotFound,
            EngineErrorCode::InternalError,
        ];

        for code in codes {
            assert!(!code.message().is_empty());
        }
    }

    #[test]
    fn backend_error_contains_backend_name() {
        let error = EngineError::backend(
            EngineErrorCode::BackendStartFailed,
            "WinDivert",
        );

        assert_eq!(
            error.code(),
            EngineErrorCode::BackendStartFailed
        );

        assert!(error.message().contains("WinDivert"));
    }

    #[test]
    fn native_error_contains_native_code() {
        let error =
            EngineError::native(EngineErrorCode::BackendInitFailed, 1234);

        assert!(error.message().contains("1234"));
    }

    #[test]
    fn recoverability_is_explicit() {
        assert!(EngineError::queue_full().is_recoverable());
        assert!(EngineError::backend_unavailable().is_recoverable());
        assert!(EngineError::capability_lost().is_recoverable());
        assert!(!EngineError::invalid_argument().is_recoverable());
        assert!(!EngineError::packet_malformed().is_recoverable());
    }

    #[test]
    fn backend_detection_is_correct() {
        assert!(EngineError::backend_init_failed().is_backend_error());
        assert!(EngineError::backend_degraded().is_backend_error());
        assert!(!EngineError::invalid_argument().is_backend_error());
    }

    #[test]
    fn display_uses_human_readable_message() {
        let error = EngineError::invalid_handle();

        assert_eq!(error.to_string(), "Invalid handle");
    }
}
