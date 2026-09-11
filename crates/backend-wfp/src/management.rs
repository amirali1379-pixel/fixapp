// crates/backend-wfp/src/management.rs
//
// User-mode WFP management support.
//
// This module contains Base Filtering Engine (BFE) sublayer management.
// Packet callout classification itself requires a kernel-mode callout driver
// and is intentionally outside this user-mode management layer.

use network_core::{EngineError, EngineErrorCode};

#[cfg(windows)]
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_BYTE_BLOB,
    FWPM_DISPLAY_DATA0,
    FWPM_SUBLAYER0,
    FwpmSubLayerAdd0,
    FwpmSubLayerDeleteByKey0,
};
#[cfg(windows)]
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
#[cfg(windows)]
use windows_sys::core::GUID;

#[cfg(windows)]
const FWP_E_ALREADY_EXISTS: u32 = 0x8032_0009;
#[cfg(windows)]
const FWP_E_NOT_FOUND: u32 = 0x8032_0008;

#[cfg(windows)]
pub(crate) const SUBLAYER_KEY: GUID = GUID {
    data1: 0x8f7d4b21,
    data2: 0x5c63,
    data3: 0x4e1f,
    data4: [0x91, 0x2a, 0x7b, 0x34, 0x6d, 0x88, 0x42, 0xf0],
};

#[cfg(windows)]
const SUBLAYER_NAME: &[u16] = &[
    b'N' as u16, b'e' as u16, b't' as u16, b'w' as u16, b'o' as u16,
    b'r' as u16, b'k' as u16, b'-' as u16, b'E' as u16, b'n' as u16,
    b'g' as u16, b'i' as u16, b'n' as u16, b'e' as u16, b' ' as u16,
    b'C' as u16, b'o' as u16, b'r' as u16, b'e' as u16, 0,
];

#[cfg(windows)]
const SUBLAYER_DESCRIPTION: &[u16] = &[
    b'P' as u16, b'r' as u16, b'o' as u16, b'j' as u16, b'e' as u16,
    b'c' as u16, b't' as u16, b' ' as u16, b'W' as u16, b'F' as u16,
    b'P' as u16, b' ' as u16, b'm' as u16, b'a' as u16, b'n' as u16,
    b'a' as u16, b'g' as u16, b'e' as u16, b'm' as u16, b'e' as u16,
    b'n' as u16, b't' as u16, 0,
];

#[cfg(windows)]
pub fn add_sublayer(engine: usize) -> Result<(), EngineError> {
    if engine == 0 {
        return Err(EngineError::backend(EngineErrorCode::InvalidHandle, "wfp"));
    }

    // FWPM_SUBLAYER0 must use the Windows SDK layout exactly:
    // subLayerKey, displayData, flags, providerKey, providerData, weight.
    let sublayer = FWPM_SUBLAYER0 {
        subLayerKey: SUBLAYER_KEY,
        displayData: FWPM_DISPLAY_DATA0 {
            name: SUBLAYER_NAME.as_ptr() as *mut u16,
            description: SUBLAYER_DESCRIPTION.as_ptr() as *mut u16,
        },
        flags: 0,
        providerKey: core::ptr::null_mut(),
        providerData: FWP_BYTE_BLOB {
            size: 0,
            data: core::ptr::null_mut(),
        },
        weight: 0x100,
    };

    let status = unsafe {
        FwpmSubLayerAdd0(
            engine as _,
            &sublayer,
            core::ptr::null_mut(),
        )
    };

    if status == ERROR_SUCCESS || status == FWP_E_ALREADY_EXISTS {
        return Ok(());
    }

    Err(EngineError::backend_native(
        EngineErrorCode::BackendInitializationFailed,
        "wfp",
        status as i32,
    ))
}

#[cfg(windows)]
pub fn remove_sublayer(engine: usize) -> Result<(), EngineError> {
    if engine == 0 {
        return Ok(());
    }

    let status = unsafe {
        FwpmSubLayerDeleteByKey0(engine as _, &SUBLAYER_KEY)
    };

    if status == ERROR_SUCCESS || status == FWP_E_NOT_FOUND {
        return Ok(());
    }

    Err(EngineError::backend_native(
        EngineErrorCode::BackendShutdownFailed,
        "wfp",
        status as i32,
    ))
}

#[cfg(not(windows))]
pub fn add_sublayer(_engine: usize) -> Result<(), EngineError> {
    Err(EngineError::backend(EngineErrorCode::BackendUnavailable, "wfp"))
}

#[cfg(not(windows))]
pub fn remove_sublayer(_engine: usize) -> Result<(), EngineError> {
    Ok(())
}