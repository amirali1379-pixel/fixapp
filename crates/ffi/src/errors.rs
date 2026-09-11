// network-engine\crates\ffi\src\errors.rs

use std::os::raw::c_int;

use network_core::{EngineError, EngineErrorCode};

pub const NE_OK: c_int = 0;

pub const NE_ERROR_INVALID_ARGUMENT: c_int = -1;
pub const NE_ERROR_INVALID_HANDLE: c_int = -2;
pub const NE_ERROR_NOT_INITIALIZED: c_int = -3;
pub const NE_ERROR_ALREADY_INITIALIZED: c_int = -4;
pub const NE_ERROR_BACKEND_UNAVAILABLE: c_int = -5;
pub const NE_ERROR_QUEUE_FULL: c_int = -6;
pub const NE_ERROR_BUFFER_EXHAUSTED: c_int = -7;
pub const NE_ERROR_ACTION_FAILED: c_int = -8;
pub const NE_ERROR_SHUTDOWN: c_int = -9;
pub const NE_ERROR_INTERNAL: c_int = -10;

pub fn result_to_c<T>(result: Result<T, EngineError>) -> c_int {
    match result {
        Ok(_) => NE_OK,
        Err(error) => match error.code() {
            EngineErrorCode::InvalidArgument
            | EngineErrorCode::NullPointer
            | EngineErrorCode::BufferTooSmall
            | EngineErrorCode::IntegerOverflow => NE_ERROR_INVALID_ARGUMENT,

            EngineErrorCode::InvalidHandle
            | EngineErrorCode::HandleReleased
            | EngineErrorCode::HandleTypeMismatch => NE_ERROR_INVALID_HANDLE,

            EngineErrorCode::NotInitialized => NE_ERROR_NOT_INITIALIZED,

            EngineErrorCode::AlreadyInitialized => NE_ERROR_ALREADY_INITIALIZED,

            EngineErrorCode::BackendUnavailable
            | EngineErrorCode::BackendNotFound
            | EngineErrorCode::BackendNotRunning
            | EngineErrorCode::BackendAlreadyRegistered
            | EngineErrorCode::BackendAlreadyRunning
            | EngineErrorCode::BackendStartFailed
            | EngineErrorCode::BackendStopFailed
            | EngineErrorCode::BackendInitializationFailed
            | EngineErrorCode::BackendShutdownFailed
            | EngineErrorCode::BackendDegraded
            | EngineErrorCode::CapabilityUnavailable
            | EngineErrorCode::CapabilityNotSupported => {
                NE_ERROR_BACKEND_UNAVAILABLE
            }

            EngineErrorCode::QueueFull
            | EngineErrorCode::Backpressure => NE_ERROR_QUEUE_FULL,

            EngineErrorCode::BufferExhausted
            | EngineErrorCode::ResourceExhausted => {
                NE_ERROR_BUFFER_EXHAUSTED
            }

            EngineErrorCode::ActionNotSupported
            | EngineErrorCode::ActionFailed
            | EngineErrorCode::PassFailed
            | EngineErrorCode::DropFailed
            | EngineErrorCode::ModifyFailed
            | EngineErrorCode::ReinjectionFailed => {
                NE_ERROR_ACTION_FAILED
            }

            EngineErrorCode::ShutdownInProgress
            | EngineErrorCode::AlreadyShutdown => NE_ERROR_SHUTDOWN,

            _ => NE_ERROR_INTERNAL,
        },
    }
}