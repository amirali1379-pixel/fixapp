// crates/ffi/src/ffi_backend.rs

use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_uint};

use backend_manager::{BackendCapability, FailoverPolicy};

use crate::api::{copy_string, error_to_c, set_last_error};
use crate::engine::{global_engine, EngineRuntime};
use crate::errors::*;
use crate::validation::validate_not_null;

fn read_name(p: *const c_char) -> Result<String, c_int> {
    if validate_not_null(p) != NE_OK {
        set_last_error("invalid backend name pointer");
        return Err(NE_ERROR_INVALID_ARGUMENT);
    }
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .map(str::to_owned)
        .map_err(|_| {
            set_last_error("backend name is not valid UTF-8");
            NE_ERROR_INVALID_ARGUMENT
        })
}

fn with_engine<T>(
    f: impl FnOnce(&EngineRuntime) -> Result<T, network_core::EngineError>,
) -> Result<T, c_int> {
    let g = global_engine().lock().map_err(|_| {
        set_last_error("engine mutex poisoned");
        NE_ERROR_INTERNAL
    })?;
    let e = g.as_ref().ok_or_else(|| {
        set_last_error("engine is not initialized");
        NE_ERROR_NOT_INITIALIZED
    })?;
    f(e).map_err(|error| error_to_c(&error))
}

fn capability_from_c(value: c_int) -> Result<BackendCapability, c_int> {
    let value = u16::try_from(value).map_err(|_| {
        set_last_error("invalid backend capability");
        NE_ERROR_INVALID_ARGUMENT
    })?;
    BackendCapability::from_u16(value).ok_or_else(|| {
        set_last_error("invalid backend capability");
        NE_ERROR_INVALID_ARGUMENT
    })
}

#[no_mangle]
pub extern "C" fn backend_health(name: *const c_char) -> c_int {
    let name = match read_name(name) { Ok(v) => v, Err(e) => return e };
    match with_engine(|e| e.backend_manager.health(&name)) {
        Ok(v) => { set_last_error("OK"); v as c_int }
        Err(e) => e,
    }
}

#[no_mangle]
pub extern "C" fn backend_capability_count(name: *const c_char) -> c_uint {
    let name = match read_name(name) { Ok(v) => v, Err(_) => return 0 };
    match with_engine(|e| e.backend_manager.capabilities(&name)) {
        Ok(v) => { set_last_error("OK"); v.len().min(c_uint::MAX as usize) as c_uint }
        Err(e) => { set_last_error("failed to query backend capabilities"); let _ = e; 0 }
    }
}

#[no_mangle]
pub extern "C" fn backend_capabilities(name: *const c_char, buffer: *mut c_char, capacity: c_uint) -> c_int {
    let name = match read_name(name) { Ok(v) => v, Err(e) => return e };
    if validate_not_null(buffer) != NE_OK {
        set_last_error("invalid backend capabilities buffer");
        return NE_ERROR_INVALID_ARGUMENT;
    }
    match with_engine(|e| e.backend_manager.capabilities(&name)) {
        Ok(set) => {
            let value = set.to_vec().iter().map(|cap| format!("{}:{}", *cap as u16, cap.as_str())).collect::<Vec<_>>().join("\n");
            copy_string(buffer, capacity, &value)
        }
        Err(e) => e,
    }
}

#[no_mangle]
pub extern "C" fn backend_runtime_info(name: *const c_char, buffer: *mut c_char, capacity: c_uint) -> c_int {
    let name = match read_name(name) { Ok(v) => v, Err(e) => return e };
    if validate_not_null(buffer) != NE_OK {
        set_last_error("invalid backend runtime buffer");
        return NE_ERROR_INVALID_ARGUMENT;
    }
    match with_engine(|e| {
        let runtime = e.backend_manager.runtime_state(&name)?;
        let health = e.backend_manager.health(&name)?;
        Ok((runtime, health))
    }) {
        Ok((runtime, health)) => {
            let native_error = runtime.last_native_error.map_or_else(|| "null".to_string(), |v| v.to_string());
            let value = format!(
                "{{\"name\":\"{}\",\"lifecycle\":{},\"health\":{},\"error_count\":{},\"last_native_error\":{}}}",
                runtime.descriptor.name,
                runtime.lifecycle as u8,
                health as u8,
                runtime.error_count,
                native_error
            );
            copy_string(buffer, capacity, &value)
        }
        Err(e) => e,
    }
}

#[no_mangle]
pub extern "C" fn backend_manager_stats(buffer: *mut c_char, capacity: c_uint) -> c_int {
    if validate_not_null(buffer) != NE_OK {
        set_last_error("invalid backend manager stats buffer");
        return NE_ERROR_INVALID_ARGUMENT;
    }
    match with_engine(|e| Ok(e.backend_manager.stats())) {
        Ok(stats) => copy_string(buffer, capacity, &format!(
            "{{\"registered\":{},\"running\":{},\"degraded\":{},\"failed\":{},\"stopped\":{},\"available\":{}}}",
            stats.registered, stats.running, stats.degraded, stats.failed, stats.stopped, stats.available()
        )),
        Err(e) => e,
    }
}

#[no_mangle]
pub extern "C" fn backend_failover_policy() -> c_int {
    match with_engine(|e| e.backend_manager.failover_policy()) {
        Ok(policy) => { set_last_error("OK"); policy as c_int }
        Err(e) => e,
    }
}

#[no_mangle]
pub extern "C" fn backend_set_failover_policy(policy: c_int) -> c_int {
    let policy = match policy {
        0 => FailoverPolicy::None,
        1 => FailoverPolicy::PreferPrimary,
        2 => FailoverPolicy::PreferHealthy,
        3 => FailoverPolicy::RoundRobin,
        _ => { set_last_error("invalid failover policy"); return NE_ERROR_INVALID_ARGUMENT; }
    };
    match with_engine(|e| e.backend_manager.set_failover_policy(policy)) {
        Ok(()) => { set_last_error("OK"); NE_OK }
        Err(e) => e,
    }
}

#[no_mangle]
pub extern "C" fn backend_select(capability: c_int, buffer: *mut c_char, capacity: c_uint) -> c_int {
    let capability = match capability_from_c(capability) { Ok(v) => v, Err(e) => return e };
    if validate_not_null(buffer) != NE_OK {
        set_last_error("invalid backend selection buffer");
        return NE_ERROR_INVALID_ARGUMENT;
    }
    match with_engine(|e| Ok(e.backend_manager.select_backend(capability))) {
        Ok(Some(name)) => copy_string(buffer, capacity, &name),
        Ok(None) => { set_last_error("no available backend provides the requested capability"); NE_ERROR_BACKEND_UNAVAILABLE }
        Err(e) => e,
    }
}

#[no_mangle]
pub extern "C" fn backend_find_capable(capability: c_int, healthy_only: c_int, buffer: *mut c_char, capacity: c_uint) -> c_int {
    let capability = match capability_from_c(capability) { Ok(v) => v, Err(e) => return e };
    if healthy_only != 0 && healthy_only != 1 {
        set_last_error("healthy_only must be 0 or 1");
        return NE_ERROR_INVALID_ARGUMENT;
    }
    if validate_not_null(buffer) != NE_OK {
        set_last_error("invalid backend candidates buffer");
        return NE_ERROR_INVALID_ARGUMENT;
    }
    match with_engine(|e| Ok(if healthy_only == 1 { e.backend_manager.find_healthy_capable(capability) } else { e.backend_manager.find_capable(capability) })) {
        Ok(names) => copy_string(buffer, capacity, &names.join("\n")),
        Err(e) => e,
    }
}

#[no_mangle]
pub extern "C" fn backend_record_success(name: *const c_char) -> c_int {
    let name = match read_name(name) { Ok(v) => v, Err(e) => return e };
    match with_engine(|e| e.backend_manager.record_success(&name)) {
        Ok(health) => { set_last_error("OK"); health as c_int }
        Err(e) => e,
    }
}

#[no_mangle]
pub extern "C" fn backend_record_failure(name: *const c_char, native_error: c_int) -> c_int {
    let name = match read_name(name) { Ok(v) => v, Err(e) => return e };
    match with_engine(|e| e.backend_manager.record_failure(&name, Some(native_error))) {
        Ok(health) => { set_last_error("OK"); health as c_int }
        Err(e) => e,
    }
}

#[no_mangle]
pub extern "C" fn backend_failover_capture(name: *const c_char, buffer: *mut c_char, capacity: c_uint) -> c_int {
    let name = match read_name(name) { Ok(v) => v, Err(e) => return e };
    if validate_not_null(buffer) != NE_OK { set_last_error("invalid failover output buffer"); return NE_ERROR_INVALID_ARGUMENT; }
    match with_engine(|e| {
        e.backend_manager.runtime_state(&name)?;
        e.failover_capture_backend(&name)
    }) {
        Ok(alternative) => copy_string(buffer, capacity, &alternative),
        Err(e) => e,
    }
}

#[no_mangle]
pub extern "C" fn backend_failover_reinjection(name: *const c_char, buffer: *mut c_char, capacity: c_uint) -> c_int {
    let name = match read_name(name) { Ok(v) => v, Err(e) => return e };
    if validate_not_null(buffer) != NE_OK { set_last_error("invalid failover output buffer"); return NE_ERROR_INVALID_ARGUMENT; }
    match with_engine(|e| {
        e.backend_manager.runtime_state(&name)?;
        e.failover_reinjection_backend(&name)
    }) {
        Ok(alternative) => copy_string(buffer, capacity, &alternative),
        Err(e) => e,
    }
}