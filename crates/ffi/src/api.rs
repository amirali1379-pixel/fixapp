// crates/ffi/src/api.rs
//
// Public C ABI implementation for network-engine.dll.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(unsafe_code)]

use std::collections::HashMap;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_uint, c_ulonglong, c_void};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use backend_manager::{
    BackendCapability,
    BackendDescriptor,
    BackendLifecycle,
    CapabilitySet,
};
use network_core::policy::{
    ForwardingPolicy,
    GatewayPolicy,
    NatPolicy,
    NatPolicyMode,
    PolicyDecision,
    RoutingContext,
};
use network_core::{
    observation::{ObservationId, PacketObservation},
    packet::Packet,
    timestamp::Timestamp,
    BackendSource,
    Direction,
    EngineError,
    EngineErrorCode,
};

use crate::engine::{global_engine, EngineRuntime};
use crate::errors::*;
use crate::handles::next_handle;
use crate::init::EngineConfig;
use crate::types::{NeGatewayConfig, NeInitConfig, NePacketDescriptor, NeStatistics};
use crate::validation::validate_not_null;

// ─────────────────────────────────────────────────────────────────────
// Packet handles
// ─────────────────────────────────────────────────────────────────────

static PACKET_HANDLES: OnceLock<Mutex<HashMap<c_ulonglong, PacketObservation>>> =
    OnceLock::new();

fn packet_handles() -> &'static Mutex<HashMap<c_ulonglong, PacketObservation>> {
    PACKET_HANDLES.get_or_init(|| Mutex::new(HashMap::new()))
}

static NEXT_INJECTED_OBSERVATION_ID: AtomicU64 = AtomicU64::new(1);

fn next_injected_observation_id() -> u64 {
    NEXT_INJECTED_OBSERVATION_ID.fetch_add(1, Ordering::Relaxed)
}

// ─────────────────────────────────────────────────────────────────────
// Last error
// ─────────────────────────────────────────────────────────────────────

static LAST_ERROR: OnceLock<Mutex<String>> = OnceLock::new();

fn last_error() -> &'static Mutex<String> {
    LAST_ERROR.get_or_init(|| Mutex::new(String::from("OK")))
}

pub(crate) fn set_last_error(message: impl Into<String>) {
    if let Ok(mut value) = last_error().lock() {
        *value = message.into();
    }
}

// ─────────────────────────────────────────────────────────────────────
// Error mapping
// ─────────────────────────────────────────────────────────────────────

pub(crate) fn error_to_c(error: &EngineError) -> c_int {
    set_last_error(error.message());
    match error.code() {
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
        | EngineErrorCode::BackendAlreadyRegistered
        | EngineErrorCode::BackendAlreadyRunning
        | EngineErrorCode::BackendNotRunning
        | EngineErrorCode::BackendStartFailed
        | EngineErrorCode::BackendStopFailed
        | EngineErrorCode::BackendInitializationFailed
        | EngineErrorCode::BackendShutdownFailed
        | EngineErrorCode::BackendDegraded
        | EngineErrorCode::CapabilityUnavailable
        | EngineErrorCode::CapabilityNotSupported => NE_ERROR_BACKEND_UNAVAILABLE,
        EngineErrorCode::QueueFull | EngineErrorCode::Backpressure => NE_ERROR_QUEUE_FULL,
        EngineErrorCode::BufferExhausted | EngineErrorCode::ResourceExhausted => {
            NE_ERROR_BUFFER_EXHAUSTED
        }
        EngineErrorCode::ActionNotSupported
        | EngineErrorCode::ActionFailed
        | EngineErrorCode::PassFailed
        | EngineErrorCode::DropFailed
        | EngineErrorCode::ModifyFailed
        | EngineErrorCode::ReinjectionFailed => NE_ERROR_ACTION_FAILED,
        EngineErrorCode::ShutdownInProgress | EngineErrorCode::AlreadyShutdown => {
            NE_ERROR_SHUTDOWN
        }
        _ => NE_ERROR_INTERNAL,
    }
}

// ─────────────────────────────────────────────────────────────────────
// String helpers
// ─────────────────────────────────────────────────────────────────────

fn read_string(p: *const c_char) -> Result<String, c_int> {
    if validate_not_null(p) != NE_OK {
        set_last_error("invalid string pointer");
        return Err(NE_ERROR_INVALID_ARGUMENT);
    }
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .map(str::to_owned)
        .map_err(|_| {
            set_last_error("string is not valid UTF-8");
            NE_ERROR_INVALID_ARGUMENT
        })
}

pub(crate) fn copy_string(p: *mut c_char, n: c_uint, s: &str) -> c_int {
    if validate_not_null(p) != NE_OK {
        set_last_error("invalid output buffer");
        return NE_ERROR_INVALID_ARGUMENT;
    }
    let bytes = s.as_bytes();
    if n == 0 || bytes.len() + 1 > n as usize {
        set_last_error("output buffer too small");
        return NE_ERROR_BUFFER_EXHAUSTED;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), p as *mut u8, bytes.len());
        *p.add(bytes.len()) = 0;
    }
    set_last_error("OK");
    NE_OK
}

// ─────────────────────────────────────────────────────────────────────
// Legacy helpers preserved from the previous `api.rs`
// ─────────────────────────────────────────────────────────────────────

#[allow(dead_code)]
fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64
}

#[allow(dead_code)]
fn lifecycle_to_c(lifecycle: BackendLifecycle) -> c_int {
    lifecycle as c_int
}

#[allow(dead_code)]
fn lifecycle_from_c(value: c_int) -> Option<BackendLifecycle> {
    match value {
        0 => Some(BackendLifecycle::Disabled),
        1 => Some(BackendLifecycle::Starting),
        2 => Some(BackendLifecycle::Running),
        3 => Some(BackendLifecycle::Degraded),
        4 => Some(BackendLifecycle::Failed),
        5 => Some(BackendLifecycle::Stopping),
        6 => Some(BackendLifecycle::Stopped),
        _ => None,
    }
}

#[allow(dead_code)]
fn backend_source_from_c(value: c_int) -> BackendSource {
    match value {
        1 => BackendSource::Wfp,
        2 => BackendSource::WinDivert,
        3 => BackendSource::Npcap,
        4 => BackendSource::IpHelper,
        5 => BackendSource::Unknown,
        6 => BackendSource::Etw,
        _ => BackendSource::Unknown,
    }
}

#[allow(dead_code)]
fn direction_from_c(value: c_int) -> Direction {
    match value {
        0 => Direction::Inbound,
        1 => Direction::Outbound,
        _ => Direction::Unknown,
    }
}

#[allow(dead_code)]
fn direction_to_c(direction: Direction) -> c_int {
    match direction {
        Direction::Inbound => 0,
        Direction::Outbound => 1,
        Direction::Unknown => 2,
    }
}

#[allow(dead_code)]
fn capability_from_c(value: c_int) -> Option<BackendCapability> {
    let value = u16::try_from(value).ok()?;
    BackendCapability::from_u16(value)
}

// ─────────────────────────────────────────────────────────────────────
// Packet handle helpers
// ─────────────────────────────────────────────────────────────────────

fn observation_context_for_windivert(observation: &PacketObservation) -> Option<&[u8]> {
    observation.native_context.as_ref().and_then(|context| {
        if context.backend == BackendSource::WinDivert {
            Some(context.bytes.as_slice())
        } else {
            None
        }
    })
}

fn restore_packet_handle(handle: c_ulonglong, observation: PacketObservation) -> c_int {
    match packet_handles().lock() {
        Ok(mut handles) => {
            if handles.insert(handle, observation).is_some() {
                set_last_error("packet handle collision while restoring ownership");
                NE_ERROR_INTERNAL
            } else {
                NE_OK
            }
        }
        Err(_) => {
            set_last_error("packet handle mutex poisoned while restoring ownership");
            NE_ERROR_INTERNAL
        }
    }
}

fn take_packet_handle(handle: c_ulonglong) -> Result<PacketObservation, c_int> {
    if handle == 0 {
        set_last_error("invalid packet handle");
        return Err(NE_ERROR_INVALID_HANDLE);
    }
    let mut handles = packet_handles().lock().map_err(|_| {
        set_last_error("packet handle mutex poisoned");
        NE_ERROR_INTERNAL
    })?;
    handles.remove(&handle).ok_or_else(|| {
        set_last_error("invalid or released packet handle");
        NE_ERROR_INVALID_HANDLE
    })
}

fn release_host_observation(
    engine: &EngineRuntime,
    observation: &PacketObservation,
) -> Result<(), c_int> {
    engine
        .packet_bus
        .release_host(observation.observation_id)
        .map_err(|error| error_to_c(&error))
        .map(|_| ())
}

fn terminal_drop(handle: c_ulonglong) -> c_int {
    let observation = match take_packet_handle(handle) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let g = match global_engine().lock() {
        Ok(v) => v,
        Err(_) => {
            let restore = restore_packet_handle(handle, observation);
            return if restore == NE_OK {
                set_last_error("engine mutex poisoned");
                NE_ERROR_INTERNAL
            } else {
                restore
            };
        }
    };
    let Some(engine) = g.as_ref() else {
        let restore = restore_packet_handle(handle, observation);
        return if restore == NE_OK {
            set_last_error("engine is not initialized");
            NE_ERROR_NOT_INITIALIZED
        } else {
            restore
        };
    };
    if let Err(code) = release_host_observation(engine, &observation) {
        let restore = restore_packet_handle(handle, observation);
        return if restore == NE_OK { code } else { restore };
    }
    drop(observation);
    engine
        .statistics
        .drops_host_requested
        .fetch_add(1, Ordering::Relaxed);
    set_last_error("OK");
    NE_OK
}

// ─────────────────────────────────────────────────────────────────────
// Lifecycle
// ─────────────────────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn network_init(c: *const NeInitConfig) -> c_int {
    if let Err(reason) = crate::native_runtime::prepare() {
        set_last_error(reason);
        // Best-effort: don't block init on this. A deployment where the
        // native DLLs are already discoverable via the normal search order
        // (PATH, next to the host executable) still works without it.
    }
    if validate_not_null(c) != NE_OK {
        set_last_error("invalid initialization pointer");
        return NE_ERROR_INVALID_ARGUMENT;
    }
    let mut g = match global_engine().lock() {
        Ok(v) => v,
        Err(_) => {
            set_last_error("engine mutex poisoned");
            return NE_ERROR_INTERNAL;
        }
    };
    if g.is_some() {
        set_last_error("engine is already initialized");
        return NE_ERROR_ALREADY_INITIALIZED;
    }
    let x = unsafe { &*c };
    if !x.is_valid() {
        set_last_error("invalid initialization configuration");
        return NE_ERROR_INVALID_ARGUMENT;
    }
    let config = EngineConfig {
        queue_capacity: x.queue_capacity as usize,
        pool_max_size: x.pool_max_size as usize,
        buffer_capacity: x.buffer_capacity as usize,
        max_flows: x.max_flows as usize,
    };
    match EngineRuntime::initialize(&config) {
        Ok(e) => {
            *g = Some(e);
            set_last_error("OK");
            NE_OK
        }
        Err(e) => error_to_c(&e),
    }
}

#[no_mangle]
pub extern "C" fn network_shutdown() -> c_int {
    let mut g = match global_engine().lock() {
        Ok(v) => v,
        Err(_) => {
            set_last_error("engine mutex poisoned");
            return NE_ERROR_INTERNAL;
        }
    };
    let Some(engine) = g.as_mut() else {
        set_last_error("engine is not initialized");
        return NE_ERROR_NOT_INITIALIZED;
    };
    match engine.shutdown() {
        Ok(()) => {
            *g = None;
            if let Ok(mut handles) = packet_handles().lock() {
                handles.clear();
            }
            set_last_error("OK");
            NE_OK
        }
        Err(error) => error_to_c(&error),
    }
}

#[no_mangle]
pub extern "C" fn network_is_initialized() -> c_int {
    match global_engine().lock() {
        Ok(g) => g.as_ref().map_or(0, |e| if e.is_initialized() { 1 } else { 0 }),
        Err(_) => 0,
    }
}

// ─────────────────────────────────────────────────────────────────────
// Backend management
// ─────────────────────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn backend_count() -> c_uint {
    match global_engine().lock() {
        Ok(g) => g.as_ref().map_or(0, |e| {
            e.backend_names().len().min(c_uint::MAX as usize) as c_uint
        }),
        Err(_) => 0,
    }
}

#[no_mangle]
pub extern "C" fn backend_list(p: *mut c_char, n: c_uint, l: c_uint) -> c_int {
    if validate_not_null(p) != NE_OK {
        set_last_error("invalid backend list buffer");
        return NE_ERROR_INVALID_ARGUMENT;
    }
    let g = match global_engine().lock() {
        Ok(v) => v,
        Err(_) => {
            set_last_error("engine mutex poisoned");
            return NE_ERROR_INTERNAL;
        }
    };
    let Some(e) = g.as_ref() else {
        set_last_error("engine is not initialized");
        return NE_ERROR_NOT_INITIALIZED;
    };
    let out = e
        .backend_names()
        .iter()
        .take(n as usize)
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    copy_string(p, l, &out)
}

#[no_mangle]
pub extern "C" fn backend_status(p: *const c_char) -> c_int {
    let n = match read_string(p) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let g = match global_engine().lock() {
        Ok(v) => v,
        Err(_) => {
            set_last_error("engine mutex poisoned");
            return NE_ERROR_INTERNAL;
        }
    };
    let Some(e) = g.as_ref() else {
        set_last_error("engine is not initialized");
        return NE_ERROR_NOT_INITIALIZED;
    };
    match e.backend_lifecycle(&n) {
        Ok(v) => {
            set_last_error("OK");
            v as c_int
        }
        Err(e) => error_to_c(&e),
    }
}

#[no_mangle]
pub extern "C" fn backend_set_status(p: *const c_char, s: c_int) -> c_int {
    let n = match read_string(p) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let g = match global_engine().lock() {
        Ok(v) => v,
        Err(_) => {
            set_last_error("engine mutex poisoned");
            return NE_ERROR_INTERNAL;
        }
    };
    let Some(e) = g.as_ref() else {
        set_last_error("engine is not initialized");
        return NE_ERROR_NOT_INITIALIZED;
    };
    let result = match s {
        2 => e.start_backend(&n),
        6 => e.stop_backend(&n),
        _ => {
            set_last_error("unsupported backend lifecycle command");
            return NE_ERROR_INVALID_ARGUMENT;
        }
    };
    match result {
        Ok(()) => {
            set_last_error("OK");
            NE_OK
        }
        Err(e) => error_to_c(&e),
    }
}

#[no_mangle]
pub extern "C" fn backend_register(name: *const c_char) -> c_int {
    let n = match read_string(name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if n.trim().is_empty() {
        set_last_error("backend name must not be empty");
        return NE_ERROR_INVALID_ARGUMENT;
    }
    let g = match global_engine().lock() {
        Ok(v) => v,
        Err(_) => {
            set_last_error("engine mutex poisoned");
            return NE_ERROR_INTERNAL;
        }
    };
    let Some(e) = g.as_ref() else {
        set_last_error("engine is not initialized");
        return NE_ERROR_NOT_INITIALIZED;
    };
    let descriptor = BackendDescriptor::new(
        &n,
        "0.1.0",
        "FFI registered backend",
        CapabilitySet::new(),
    );
    match e.register_backend(descriptor) {
        Ok(()) => {
            set_last_error("OK");
            NE_OK
        }
        Err(error) => error_to_c(&error),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Capture
// ─────────────────────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn capture_start() -> c_int {
    let g = match global_engine().lock() {
        Ok(v) => v,
        Err(_) => {
            set_last_error("engine mutex poisoned");
            return NE_ERROR_INTERNAL;
        }
    };
    let Some(e) = g.as_ref() else {
        set_last_error("engine is not initialized");
        return NE_ERROR_NOT_INITIALIZED;
    };
    match e.capture_start() {
        Ok(()) => {
            set_last_error("OK");
            NE_OK
        }
        Err(error) => error_to_c(&error),
    }
}

#[no_mangle]
pub extern "C" fn capture_stop() -> c_int {
    let g = match global_engine().lock() {
        Ok(v) => v,
        Err(_) => {
            set_last_error("engine mutex poisoned");
            return NE_ERROR_INTERNAL;
        }
    };
    let Some(e) = g.as_ref() else {
        set_last_error("engine is not initialized");
        return NE_ERROR_NOT_INITIALIZED;
    };
    match e.capture_stop() {
        Ok(()) => {
            set_last_error("OK");
            NE_OK
        }
        Err(error) => error_to_c(&error),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Packet injection and reading
// ─────────────────────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn packet_inject(
    p: *const c_void,
    n: c_uint,
    s: c_int,
    d: c_int,
    i: c_uint,
) -> c_int {
    if validate_not_null(p) != NE_OK || n == 0 {
        set_last_error("invalid packet input");
        return NE_ERROR_INVALID_ARGUMENT;
    }
    let bytes = unsafe { std::slice::from_raw_parts(p as *const u8, n as usize) }.to_vec();
    let source = match s {
        0 => BackendSource::WinDivert,
        1 => BackendSource::Npcap,
        2 => BackendSource::Wfp,
        _ => {
            set_last_error("invalid backend source");
            return NE_ERROR_INVALID_ARGUMENT;
        }
    };
    let direction = match d {
        0 => Direction::Inbound,
        1 => Direction::Outbound,
        _ => {
            set_last_error("invalid packet direction");
            return NE_ERROR_INVALID_ARGUMENT;
        }
    };
    let observation = PacketObservation::new(
        ObservationId::new(next_injected_observation_id()),
        source,
        Timestamp::now(),
        Timestamp::now(),
        direction,
        (i as u64).to_string(),
        Packet::new(bytes),
    );
    let g = match global_engine().lock() {
        Ok(v) => v,
        Err(_) => {
            set_last_error("engine mutex poisoned");
            return NE_ERROR_INTERNAL;
        }
    };
    let Some(e) = g.as_ref() else {
        set_last_error("engine is not initialized");
        return NE_ERROR_NOT_INITIALIZED;
    };
    match e.ingest_observation(observation) {
        Ok(()) => {
            set_last_error("OK");
            NE_OK
        }
        Err(e) => error_to_c(&e),
    }
}

#[no_mangle]
pub extern "C" fn packet_read(p: *mut NePacketDescriptor) -> c_int {
    if validate_not_null(p) != NE_OK {
        set_last_error("invalid packet descriptor pointer");
        return NE_ERROR_INVALID_ARGUMENT;
    }
    let g = match global_engine().lock() {
        Ok(v) => v,
        Err(_) => {
            set_last_error("engine mutex poisoned");
            return NE_ERROR_INTERNAL;
        }
    };
    let Some(e) = g.as_ref() else {
        set_last_error("engine is not initialized");
        return NE_ERROR_NOT_INITIALIZED;
    };
    let observation = match e.packet_bus.try_read() {
        Ok(Some(v)) => v,
        Ok(None) => {
            set_last_error("packet queue is empty");
            return NE_ERROR_QUEUE_FULL;
        }
        Err(error) => return error_to_c(&error),
    };
    if let Err(error) = e.process_observation(&observation) {
        let _ = e.packet_bus.requeue_processing(observation);
        return error_to_c(&error);
    }
    if observation.packet.len() > c_uint::MAX as usize {
        let _ = e.packet_bus.requeue_processing(observation);
        set_last_error("packet is too large for C ABI length");
        return NE_ERROR_BUFFER_EXHAUSTED;
    }
    let id = observation.observation_id;
    let handle = next_handle();
    let mut handles = match packet_handles().lock() {
        Ok(v) => v,
        Err(_) => {
            let _ = e.packet_bus.requeue_processing(observation);
            set_last_error("packet handle mutex poisoned");
            return NE_ERROR_INTERNAL;
        }
    };
    if handles.contains_key(&handle) {
        let _ = e.packet_bus.requeue_processing(observation);
        set_last_error("packet handle collision");
        return NE_ERROR_INTERNAL;
    }
    handles.insert(handle, observation);
    if let Err(error) = e.packet_bus.transfer_to_host(id) {
        let observation = handles
            .remove(&handle)
            .expect("packet handle insertion must succeed before ownership transfer");
        let _ = e.packet_bus.requeue_processing(observation);
        return error_to_c(&error);
    }
    let Some(entry) = handles.get(&handle) else {
        let observation = handles
            .remove(&handle)
            .expect("packet handle lookup failure must remove inserted observation");
        let _ = e.packet_bus.release_host(id);
        let _ = e.packet_bus.requeue_processing(observation);
        set_last_error("packet handle lookup failed");
        return NE_ERROR_INTERNAL;
    };
    unsafe {
        (*p).packet_handle = handle;
        (*p).data = entry.packet.as_slice().as_ptr() as *const c_void;
        (*p).len = entry.packet.len() as c_uint;
        (*p).backend_source = entry.backend_source as c_int;
        (*p).direction = entry.direction as c_int;
    }
    set_last_error("OK");
    NE_OK
}

#[no_mangle]
pub extern "C" fn packet_release(h: c_ulonglong) -> c_int {
    let observation = match take_packet_handle(h) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let g = match global_engine().lock() {
        Ok(v) => v,
        Err(_) => {
            let restore = restore_packet_handle(h, observation);
            return if restore == NE_OK {
                set_last_error("engine mutex poisoned");
                NE_ERROR_INTERNAL
            } else {
                restore
            };
        }
    };
    let Some(e) = g.as_ref() else {
        let restore = restore_packet_handle(h, observation);
        return if restore == NE_OK {
            set_last_error("engine is not initialized");
            NE_ERROR_NOT_INITIALIZED
        } else {
            restore
        };
    };
    match release_host_observation(e, &observation) {
        Ok(()) => {
            drop(observation);
            set_last_error("OK");
            NE_OK
        }
        Err(code) => {
            let restore = restore_packet_handle(h, observation);
            if restore != NE_OK {
                restore
            } else {
                code
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn packet_pass(h: c_ulonglong) -> c_int {
    let observation = match take_packet_handle(h) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let Some(context) = observation_context_for_windivert(&observation) else {
        set_last_error("packet has no native WinDivert action context");
        let restore = restore_packet_handle(h, observation);
        return if restore == NE_OK {
            NE_ERROR_ACTION_FAILED
        } else {
            restore
        };
    };
    let g = match global_engine().lock() {
        Ok(v) => v,
        Err(_) => {
            let restore = restore_packet_handle(h, observation);
            return if restore == NE_OK {
                set_last_error("engine mutex poisoned");
                NE_ERROR_INTERNAL
            } else {
                restore
            };
        }
    };
    let Some(e) = g.as_ref() else {
        let restore = restore_packet_handle(h, observation);
        return if restore == NE_OK {
            set_last_error("engine is not initialized");
            NE_ERROR_NOT_INITIALIZED
        } else {
            restore
        };
    };
    match e.windivert_reinject(observation.packet.as_slice(), context) {
        Ok(()) => {
            if let Err(code) = release_host_observation(e, &observation) {
                let restore = restore_packet_handle(h, observation);
                return if restore == NE_OK { code } else { restore };
            }
            e.statistics.packets_forwarded.fetch_add(1, Ordering::Relaxed);
            set_last_error("OK");
            NE_OK
        }
        Err(error) => {
            let restore = restore_packet_handle(h, observation);
            if restore != NE_OK {
                return restore;
            }
            error_to_c(&error)
        }
    }
}

#[no_mangle]
pub extern "C" fn packet_drop(h: c_ulonglong) -> c_int {
    terminal_drop(h)
}

#[no_mangle]
pub extern "C" fn packet_modify(h: c_ulonglong, p: *const c_void, n: c_uint) -> c_int {
    if validate_not_null(p) != NE_OK || n == 0 {
        set_last_error("invalid modified packet input");
        return NE_ERROR_INVALID_ARGUMENT;
    }
    let modified = unsafe { std::slice::from_raw_parts(p as *const u8, n as usize) }.to_vec();
    let observation = match take_packet_handle(h) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let Some(context) = observation_context_for_windivert(&observation) else {
        set_last_error("packet has no native WinDivert action context");
        let restore = restore_packet_handle(h, observation);
        return if restore == NE_OK {
            NE_ERROR_ACTION_FAILED
        } else {
            restore
        };
    };
    let g = match global_engine().lock() {
        Ok(v) => v,
        Err(_) => {
            let restore = restore_packet_handle(h, observation);
            return if restore == NE_OK {
                set_last_error("engine mutex poisoned");
                NE_ERROR_INTERNAL
            } else {
                restore
            };
        }
    };
    let Some(e) = g.as_ref() else {
        let restore = restore_packet_handle(h, observation);
        return if restore == NE_OK {
            set_last_error("engine is not initialized");
            NE_ERROR_NOT_INITIALIZED
        } else {
            restore
        };
    };
    match e.windivert_reinject(&modified, context) {
        Ok(()) => {
            if let Err(code) = release_host_observation(e, &observation) {
                let restore = restore_packet_handle(h, observation);
                return if restore == NE_OK { code } else { restore };
            }
            e.statistics.packets_forwarded.fetch_add(1, Ordering::Relaxed);
            e.statistics
                .modifications_applied
                .fetch_add(1, Ordering::Relaxed);
            set_last_error("OK");
            NE_OK
        }
        Err(error) => {
            let restore = restore_packet_handle(h, observation);
            if restore != NE_OK {
                return restore;
            }
            error_to_c(&error)
        }
    }
}

#[no_mangle]
pub extern "C" fn packet_reinject(h: c_ulonglong) -> c_int {
    let observation = match take_packet_handle(h) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let Some(context) = observation_context_for_windivert(&observation) else {
        set_last_error("packet has no native WinDivert action context");
        let restore = restore_packet_handle(h, observation);
        return if restore == NE_OK {
            NE_ERROR_ACTION_FAILED
        } else {
            restore
        };
    };
    let g = match global_engine().lock() {
        Ok(v) => v,
        Err(_) => {
            let restore = restore_packet_handle(h, observation);
            return if restore == NE_OK {
                set_last_error("engine mutex poisoned");
                NE_ERROR_INTERNAL
            } else {
                restore
            };
        }
    };
    let Some(e) = g.as_ref() else {
        let restore = restore_packet_handle(h, observation);
        return if restore == NE_OK {
            set_last_error("engine is not initialized");
            NE_ERROR_NOT_INITIALIZED
        } else {
            restore
        };
    };
    match e.windivert_reinject(observation.packet.as_slice(), context) {
        Ok(()) => {
            if let Err(code) = release_host_observation(e, &observation) {
                let restore = restore_packet_handle(h, observation);
                return if restore == NE_OK { code } else { restore };
            }
            e.statistics.packets_forwarded.fetch_add(1, Ordering::Relaxed);
            set_last_error("OK");
            NE_OK
        }
        Err(error) => {
            let restore = restore_packet_handle(h, observation);
            if restore != NE_OK {
                return restore;
            }
            error_to_c(&error)
        }
    }
}

#[no_mangle]
pub extern "C" fn packet_action(h: c_ulonglong, a: c_int) -> c_int {
    match a {
        0 => packet_pass(h),
        1 => packet_drop(h),
        2 => {
            set_last_error("MODIFY requires packet_modify(data, len)");
            NE_ERROR_INVALID_ARGUMENT
        }
        3 => packet_reinject(h),
        _ => {
            set_last_error("invalid packet action");
            NE_ERROR_INVALID_ARGUMENT
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Statistics
// ─────────────────────────────────────────────────────────────────────

fn fill_statistics(p: *mut NeStatistics) -> c_int {
    if validate_not_null(p) != NE_OK {
        set_last_error("invalid statistics pointer");
        return NE_ERROR_INVALID_ARGUMENT;
    }
    let g = match global_engine().lock() {
        Ok(v) => v,
        Err(_) => {
            set_last_error("engine mutex poisoned");
            return NE_ERROR_INTERNAL;
        }
    };
    let Some(e) = g.as_ref() else {
        set_last_error("engine is not initialized");
        return NE_ERROR_NOT_INITIALIZED;
    };
    let f = match e.flow_table.lock() {
        Ok(v) => v.stats(),
        Err(_) => {
            set_last_error("flow table mutex poisoned");
            return NE_ERROR_INTERNAL;
        }
    };
    let s = &*e.statistics;
    unsafe {
        (*p).packets_received = s.total_packets_received.load(Ordering::Relaxed);
        (*p).bytes_received = s.total_bytes_received.load(Ordering::Relaxed);
        (*p).packets_dropped = s.drops_host_requested.load(Ordering::Relaxed)
            + s.drops_safety_error.load(Ordering::Relaxed)
            + s.drops_backend_failure.load(Ordering::Relaxed);
        (*p).packets_forwarded = s.gateway_packets_forwarded.load(Ordering::Relaxed)
            + s.packets_forwarded.load(Ordering::Relaxed);
        (*p).flows_active = f.current_entries as c_ulonglong;
    }
    set_last_error("OK");
    NE_OK
}

#[no_mangle]
pub extern "C" fn engine_statistics(p: *mut NeStatistics) -> c_int {
    fill_statistics(p)
}

#[no_mangle]
pub extern "C" fn network_stats(p: *mut NeStatistics) -> c_int {
    fill_statistics(p)
}

#[no_mangle]
pub extern "C" fn bus_queue_depth() -> c_uint {
    match global_engine().lock() {
        Ok(g) => g.as_ref().map_or(0, |e| {
            e.packet_bus.len().min(c_uint::MAX as usize) as c_uint
        }),
        Err(_) => 0,
    }
}

#[no_mangle]
pub extern "C" fn bus_queue_capacity() -> c_uint {
    match global_engine().lock() {
        Ok(g) => g.as_ref().map_or(0, |e| {
            e.packet_bus.capacity().min(c_uint::MAX as usize) as c_uint
        }),
        Err(_) => 0,
    }
}

// ─────────────────────────────────────────────────────────────────────
// Flows
// ─────────────────────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn flow_count() -> c_uint {
    match global_engine().lock() {
        Ok(g) => g.as_ref().map_or(0, |e| {
            e.flow_table
                .lock()
                .map_or(0, |f| f.len().min(c_uint::MAX as usize) as c_uint)
        }),
        Err(_) => 0,
    }
}

#[no_mangle]
pub extern "C" fn flow_get(p: *mut c_char, n: c_uint) -> c_int {
    if validate_not_null(p) != NE_OK {
        set_last_error("invalid flow output buffer");
        return NE_ERROR_INVALID_ARGUMENT;
    }
    let g = match global_engine().lock() {
        Ok(v) => v,
        Err(_) => {
            set_last_error("engine mutex poisoned");
            return NE_ERROR_INTERNAL;
        }
    };
    let Some(e) = g.as_ref() else {
        set_last_error("engine is not initialized");
        return NE_ERROR_NOT_INITIALIZED;
    };
    let s = match e.flow_table.lock() {
        Ok(v) => v.stats(),
        Err(_) => {
            set_last_error("flow table mutex poisoned");
            return NE_ERROR_INTERNAL;
        }
    };
    copy_string(
        p,
        n,
        &format!(
            "{{\"current_entries\":{},\"max_entries\":{},\"total_created\":{},\"total_removed\":{},\"total_expired\":{}}}",
            s.current_entries, s.max_entries, s.total_created, s.total_removed, s.total_expired
        ),
    )
}

#[no_mangle]
pub extern "C" fn flow_stats(
    key: *const c_char,
    p: *mut c_ulonglong,
    b: *mut c_ulonglong,
) -> c_int {
    if validate_not_null(key) != NE_OK {
        set_last_error("invalid flow key pointer");
        return NE_ERROR_INVALID_ARGUMENT;
    }
    if p.is_null() && b.is_null() {
        set_last_error("at least one flow statistic output is required");
        return NE_ERROR_INVALID_ARGUMENT;
    }
    let key = match read_string(key) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let g = match global_engine().lock() {
        Ok(v) => v,
        Err(_) => {
            set_last_error("engine mutex poisoned");
            return NE_ERROR_INTERNAL;
        }
    };
    let Some(e) = g.as_ref() else {
        set_last_error("engine is not initialized");
        return NE_ERROR_NOT_INITIALIZED;
    };
    let table = match e.flow_table.lock() {
        Ok(v) => v,
        Err(_) => {
            set_last_error("flow table mutex poisoned");
            return NE_ERROR_INTERNAL;
        }
    };
    let Some(flow) = table.values().find(|flow| flow.key.to_string() == key) else {
        set_last_error(format!("flow not found: {}", key));
        return NE_ERROR_INVALID_ARGUMENT;
    };
    unsafe {
        if !p.is_null() {
            *p = flow.packet_count() as c_ulonglong;
        }
        if !b.is_null() {
            *b = flow.byte_count() as c_ulonglong;
        }
    }
    set_last_error("OK");
    NE_OK
}

#[no_mangle]
pub extern "C" fn flow_clear_expired() -> c_uint {
    let g = match global_engine().lock() {
        Ok(v) => v,
        Err(_) => {
            set_last_error("engine mutex poisoned");
            return 0;
        }
    };
    let Some(e) = g.as_ref() else {
        set_last_error("engine is not initialized");
        return 0;
    };
    let mut table = match e.flow_table.lock() {
        Ok(v) => v,
        Err(_) => {
            set_last_error("flow table mutex poisoned");
            return 0;
        }
    };
    let count = table.expire_idle_now();
    set_last_error("OK");
    count.min(c_uint::MAX as usize) as c_uint
}

// ─────────────────────────────────────────────────────────────────────
// Network state JSON helpers
// ─────────────────────────────────────────────────────────────────────

fn state_json(k: &str) -> Result<String, c_int> {
    let g = global_engine().lock().map_err(|_| NE_ERROR_INTERNAL)?;
    let e = g.as_ref().ok_or(NE_ERROR_NOT_INITIALIZED)?;
    let s = e.network_state.lock().map_err(|_| NE_ERROR_INTERNAL)?;
    let x = s.snapshot();

    let value = match k {
        "interfaces" => format!(
            "[{}]",
            x.interfaces
                .iter()
                .map(|v| format!(
                    "{{\"id\":{},\"name\":\"{}\",\"description\":\"{}\",\"kind\":\"{}\",\"state\":\"{}\",\"mtu\":{},\"if_index\":{}}}",
                    v.id,
                    v.name,
                    v.description,
                    v.kind,
                    v.state,
                    v.mtu,
                    v.if_index
                        .map(|q| q.to_string())
                        .unwrap_or_else(|| "null".into())
                ))
                .collect::<Vec<_>>()
                .join(",")
        ),
        "routes" => format!(
            "[{}]",
            x.routes
                .iter()
                .map(|v| format!(
                    "{{\"id\":{},\"destination\":\"{}\",\"prefix_length\":{},\"interface_id\":{},\"metric\":{},\"enabled\":{}}}",
                    v.id, v.destination, v.prefix_length, v.interface_id, v.metric, v.enabled
                ))
                .collect::<Vec<_>>()
                .join(",")
        ),
        _ => format!(
            "[{}]",
            x.neighbors
                .iter()
                .map(|v| format!(
                    "{{\"interface_id\":{},\"ip\":\"{}\",\"state\":\"{}\",\"is_router\":{}}}",
                    v.interface_id, v.ip_address, v.state, v.is_router
                ))
                .collect::<Vec<_>>()
                .join(",")
        ),
    };

    Ok(value)
}

#[no_mangle]
pub extern "C" fn interface_list(p: *mut c_char, n: c_uint) -> c_int {
    match state_json("interfaces") {
        Ok(v) => copy_string(p, n, &v),
        Err(e) => e,
    }
}

#[no_mangle]
pub extern "C" fn route_list(p: *mut c_char, n: c_uint) -> c_int {
    match state_json("routes") {
        Ok(v) => copy_string(p, n, &v),
        Err(e) => e,
    }
}

#[no_mangle]
pub extern "C" fn neighbor_list(p: *mut c_char, n: c_uint) -> c_int {
    match state_json("neighbors") {
        Ok(v) => copy_string(p, n, &v),
        Err(e) => e,
    }
}

#[no_mangle]
pub extern "C" fn interface_info(i: c_uint, p: *mut c_char, n: c_uint) -> c_int {
    if validate_not_null(p) != NE_OK {
        set_last_error("invalid interface output buffer");
        return NE_ERROR_INVALID_ARGUMENT;
    }
    let g = match global_engine().lock() {
        Ok(v) => v,
        Err(_) => {
            set_last_error("engine mutex poisoned");
            return NE_ERROR_INTERNAL;
        }
    };
    let Some(e) = g.as_ref() else {
        set_last_error("engine is not initialized");
        return NE_ERROR_NOT_INITIALIZED;
    };
    let s = match e.network_state.lock() {
        Ok(v) => v,
        Err(_) => {
            set_last_error("network state mutex poisoned");
            return NE_ERROR_INTERNAL;
        }
    };
    let Some(v) = s
        .snapshot()
        .interfaces
        .into_iter()
        .find(|v| v.id == i as u64 || v.if_index == Some(i))
    else {
        set_last_error("interface not found");
        return NE_ERROR_INVALID_ARGUMENT;
    };
    copy_string(
        p,
        n,
        &format!(
            "{{\"id\":{},\"name\":\"{}\",\"description\":\"{}\",\"kind\":\"{}\",\"state\":\"{}\",\"mtu\":{},\"if_index\":{}}}",
            v.id,
            v.name,
            v.description,
            v.kind,
            v.state,
            v.mtu,
            v.if_index
                .map(|q| q.to_string())
                .unwrap_or_else(|| "null".into())
        ),
    )
}

// ─────────────────────────────────────────────────────────────────────
// Gateway
// ─────────────────────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn gateway_start() -> c_int {
    let g = match global_engine().lock() {
        Ok(v) => v,
        Err(_) => {
            set_last_error("engine mutex poisoned");
            return NE_ERROR_INTERNAL;
        }
    };
    let Some(e) = g.as_ref() else {
        set_last_error("engine is not initialized");
        return NE_ERROR_NOT_INITIALIZED;
    };
    match e.gateway_start() {
        Ok(()) => {
            set_last_error("OK");
            NE_OK
        }
        Err(error) => error_to_c(&error),
    }
}

#[no_mangle]
pub extern "C" fn gateway_stop() -> c_int {
    let g = match global_engine().lock() {
        Ok(v) => v,
        Err(_) => {
            set_last_error("engine mutex poisoned");
            return NE_ERROR_INTERNAL;
        }
    };
    let Some(e) = g.as_ref() else {
        set_last_error("engine is not initialized");
        return NE_ERROR_NOT_INITIALIZED;
    };
    match e.gateway_stop() {
        Ok(()) => {
            set_last_error("OK");
            NE_OK
        }
        Err(error) => error_to_c(&error),
    }
}

#[no_mangle]
pub extern "C" fn gateway_status() -> c_int {
    match global_engine().lock() {
        Ok(g) => g.as_ref().map_or(0, |e| {
            if e.gateway_is_running() { 1 } else { 0 }
        }),
        Err(_) => 0,
    }
}

#[no_mangle]
pub extern "C" fn gateway_config(p: *const NeGatewayConfig) -> c_int {
    if validate_not_null(p) != NE_OK {
        set_last_error("invalid gateway configuration pointer");
        return NE_ERROR_INVALID_ARGUMENT;
    }
    let c = unsafe { *p };
    if c.enabled > 1
        || c.default_decision > 1
        || c.nat_enabled > 1
        || c.forwarding_enabled > 1
    {
        set_last_error("gateway boolean fields must be 0 or 1");
        return NE_ERROR_INVALID_ARGUMENT;
    }
    let nat_mode = match c.nat_mode {
        0 => NatPolicyMode::Disabled,
        1 => NatPolicyMode::SourceNat,
        2 => NatPolicyMode::DestinationNat,
        3 => NatPolicyMode::Masquerade,
        _ => {
            set_last_error("invalid NAT mode");
            return NE_ERROR_INVALID_ARGUMENT;
        }
    };
    let nat = NatPolicy {
        enabled: c.nat_enabled != 0,
        mode: nat_mode,
        external_interface_id: (c.external_interface_id != 0)
            .then_some(c.external_interface_id),
    };
    let forwarding = ForwardingPolicy {
        enabled: c.forwarding_enabled != 0,
        ingress_interface_id: (c.ingress_interface_id != 0)
            .then_some(c.ingress_interface_id),
        egress_interface_id: (c.egress_interface_id != 0)
            .then_some(c.egress_interface_id),
        decision: if c.default_decision != 0 {
            PolicyDecision::Allow
        } else {
            PolicyDecision::Deny
        },
    };
    let policy = GatewayPolicy {
        enabled: c.enabled != 0,
        default_decision: if c.default_decision != 0 {
            PolicyDecision::Allow
        } else {
            PolicyDecision::Deny
        },
        nat: Some(nat),
        forwarding: Some(forwarding),
        routing: RoutingContext {
            table_id: c.routing_table_id,
            preferred_interface_id: (c.preferred_interface_id != 0)
                .then_some(c.preferred_interface_id),
        },
    };
    if let Err(error) = policy.validate() {
        return error_to_c(&error);
    }
    let g = match global_engine().lock() {
        Ok(v) => v,
        Err(_) => {
            set_last_error("engine mutex poisoned");
            return NE_ERROR_INTERNAL;
        }
    };
    let Some(e) = g.as_ref() else {
        set_last_error("engine is not initialized");
        return NE_ERROR_NOT_INITIALIZED;
    };
    match e.gateway_config(policy) {
        Ok(()) => {
            set_last_error("OK");
            NE_OK
        }
        Err(error) => error_to_c(&error),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Pool, version, capability, last error
// ─────────────────────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn pool_allocated_count() -> c_uint {
    match global_engine().lock() {
        Ok(g) => g.as_ref().map_or(0, |e| {
            e.buffer_pool.allocated().min(c_uint::MAX as usize) as c_uint
        }),
        Err(_) => 0,
    }
}

#[no_mangle]
pub extern "C" fn pool_available_count() -> c_uint {
    match global_engine().lock() {
        Ok(g) => g.as_ref().map_or(0, |e| {
            e.buffer_pool.available().min(c_uint::MAX as usize) as c_uint
        }),
        Err(_) => 0,
    }
}

#[no_mangle]
pub extern "C" fn engine_version(p: *mut c_char, n: c_uint) -> c_int {
    copy_string(p, n, "0.1.0")
}

#[no_mangle]
pub extern "C" fn capability_check(name: *const c_char, c: c_int) -> c_int {
    let n = match read_string(name) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let Ok(cv) = u16::try_from(c) else {
        return 0;
    };
    let Some(cap) = BackendCapability::from_u16(cv) else {
        return 0;
    };
    match global_engine().lock() {
        Ok(g) => g.as_ref().map_or(0, |e| {
            match e.backend_manager.supports(&n, cap) {
                Ok(v) => if v { 1 } else { 0 },
                Err(error) => {
                    set_last_error(error.message());
                    0
                }
            }
        }),
        Err(_) => 0,
    }
}

#[no_mangle]
pub extern "C" fn last_error_message(p: *mut c_char, n: c_uint) -> c_int {
    let message = match last_error().lock() {
        Ok(value) => value.clone(),
        Err(_) => String::from("internal error: last-error state unavailable"),
    };
    copy_string(p, n, &message)
}