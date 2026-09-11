use std::ffi::CString;
use std::os::raw::c_char;

#[test]
fn ffi_null_pointer_validation_is_rejected() {
    assert_ne!(ffi::validation::validate_not_null(std::ptr::null::<c_char>()), ffi::errors::NE_OK);
}

#[test]
fn ffi_non_null_pointer_validation_is_accepted() {
    let value = 1u8;
    assert_eq!(ffi::validation::validate_not_null(&value as *const u8), ffi::errors::NE_OK);
}

#[test]
fn ffi_handle_zero_is_invalid() {
    assert_eq!(ffi::validation::validate_handle(0), ffi::errors::NE_ERROR_INVALID_HANDLE);
}

#[test]
fn ffi_handle_nonzero_is_valid() {
    assert_eq!(ffi::validation::validate_handle(1), ffi::errors::NE_OK);
    assert_eq!(ffi::validation::validate_handle(u64::MAX), ffi::errors::NE_OK);
}

#[test]
fn ffi_string_validation_requires_terminator() {
    let value = CString::new("backend").unwrap();
    assert_eq!(ffi::validation::validate_string(value.as_ptr(), value.as_bytes_with_nul().len()), ffi::errors::NE_OK);
    assert_ne!(ffi::validation::validate_string(value.as_ptr(), value.as_bytes().len()), ffi::errors::NE_OK);
}

#[test]
fn ffi_string_validation_rejects_zero_length_and_null() {
    let value = CString::new("backend").unwrap();
    assert_ne!(ffi::validation::validate_string(value.as_ptr(), 0), ffi::errors::NE_OK);
    assert_ne!(ffi::validation::validate_string(std::ptr::null(), 1), ffi::errors::NE_OK);
}

#[test]
fn ffi_string_validation_does_not_accept_terminator_outside_bound() {
    let value = CString::new("backend").unwrap();
    let without_terminator = value.as_bytes();
    assert_ne!(
        ffi::validation::validate_string(
            without_terminator.as_ptr() as *const c_char,
            without_terminator.len(),
        ),
        ffi::errors::NE_OK,
    );
}
