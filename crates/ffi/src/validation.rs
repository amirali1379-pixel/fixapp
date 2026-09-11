// network-engine\crates\ffi\src\validation.rs

use std::os::raw::{c_char, c_int};

use crate::errors::{
    NE_ERROR_INVALID_ARGUMENT,
    NE_ERROR_INVALID_HANDLE,
    NE_OK,
};

/// Validate that a pointer supplied by the C caller is non-null.
pub fn validate_not_null<T>(ptr: *const T) -> c_int {
    if ptr.is_null() {
        NE_ERROR_INVALID_ARGUMENT
    } else {
        NE_OK
    }
}

/// Validate that a C string pointer is non-null and contains a
/// terminating NUL byte within the supplied maximum length.
///
/// The function never reads beyond `max_len` bytes.
pub fn validate_string(ptr: *const c_char, max_len: usize) -> c_int {
    if ptr.is_null() || max_len == 0 {
        return NE_ERROR_INVALID_ARGUMENT;
    }

    let bytes = unsafe {
        std::slice::from_raw_parts(ptr as *const u8, max_len)
    };

    if bytes.iter().any(|&byte| byte == 0) {
        NE_OK
    } else {
        NE_ERROR_INVALID_ARGUMENT
    }
}

/// Validate an opaque FFI handle.
///
/// Handle value 0 is reserved for NULL/invalid.
pub fn validate_handle(handle: u64) -> c_int {
    if handle == 0 {
        NE_ERROR_INVALID_HANDLE
    } else {
        NE_OK
    }
}