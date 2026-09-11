// crates/ffi/src/capture_api.rs
//
// Capture-related C ABI entry points.
//
// The live EngineRuntime uses a thread-based capture pipeline
// (`capture_start` / `capture_stop`). Legacy poll-based capture
// entry points are preserved here as compatibility shims that map
// onto the current runtime API where possible, and report a clear
// error otherwise.

use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_uint};

use crate::{
    engine::global_engine,
    errors::{
        NE_ERROR_INTERNAL,
        NE_ERROR_INVALID_ARGUMENT,
        NE_ERROR_NOT_INITIALIZED,
        NE_OK,
    },
    validation::validate_not_null,
};

/// Legacy poll entry point.
///
/// The current EngineRuntime owns a capture worker thread that polls
/// the native backend internally; there is no separate poll step
/// exposed through the C ABI.
#[no_mangle]
pub extern "C" fn capture_poll() -> c_int {
    NE_ERROR_NOT_INITIALIZED
}

/// Processes a single queued observation synchronously.
///
/// Equivalent to `EngineRuntime::process_one`.
#[no_mangle]
pub extern "C" fn capture_process() -> c_int {
    let g = match global_engine().lock() {
        Ok(v) => v,
        Err(_) => return NE_ERROR_INTERNAL,
    };
    let Some(engine) = g.as_ref() else {
        return NE_ERROR_NOT_INITIALIZED;
    };
    match engine.process_one() {
        Ok(_) => NE_OK,
        Err(_) => NE_ERROR_INTERNAL,
    }
}

/// Legacy "process and apply" entry point.
///
/// The current EngineRuntime applies Host-controlled actions inside
/// the capture worker; there is no separate apply step exposed here.
#[no_mangle]
pub extern "C" fn capture_process_and_apply() -> c_int {
    NE_ERROR_NOT_INITIALIZED
}

/// Returns 1 when the Packet Bus has observations waiting.
#[no_mangle]
pub extern "C" fn capture_process_has_work() -> c_int {
    let guard = match global_engine().lock() {
        Ok(guard) => guard,
        Err(_) => return 0,
    };
    let Some(engine) = guard.as_ref() else {
        return 0;
    };
    if engine.packet_bus.is_empty() { 0 } else { 1 }
}

/// Legacy Npcap capture entry point.
///
/// Npcap capture is started through the normal backend lifecycle
/// (`start_backend("npcap")`). This entry point validates its
/// arguments and reports that the dedicated path is not available
/// on the current EngineRuntime.
#[no_mangle]
pub extern "C" fn capture_start_npcap(
    interface_index: c_uint,
    device_name: *const c_char,
) -> c_int {
    if interface_index == 0 || validate_not_null(device_name) != NE_OK {
        return NE_ERROR_INVALID_ARGUMENT;
    }
    let device_name = unsafe { CStr::from_ptr(device_name) };
    let device_name = match device_name.to_str() {
        Ok(value) if !value.trim().is_empty() => value,
        _ => return NE_ERROR_INVALID_ARGUMENT,
    };
    let _ = device_name;
    NE_ERROR_NOT_INITIALIZED
}