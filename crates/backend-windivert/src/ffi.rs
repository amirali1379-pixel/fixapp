//! WinDivert FFI. The third-party DLL is loaded explicitly from the
//! packaged runtime location rather than relying on the process DLL search path.

use std::os::raw::{c_char, c_void};

pub const WINDIVERT_LAYER_NETWORK: u8 = 0;
pub const WINDIVERT_LAYER_NETWORK_FORWARD: u8 = 1;
pub const WINDIVERT_LAYER_FLOW: u8 = 2;
pub const WINDIVERT_LAYER_SOCKET: u8 = 3;
pub const WINDIVERT_LAYER_REFLECT: u8 = 4;
pub const WINDIVERT_FLAG_SNIFF: u64 = 0x0001;
pub const WINDIVERT_FLAG_DROP: u64 = 0x0002;
pub const WINDIVERT_FLAG_RECV_ONLY: u64 = 0x0004;
pub const WINDIVERT_FLAG_SEND_ONLY: u64 = 0x0008;
pub const WINDIVERT_FLAG_NO_INSTALL: u64 = 0x0010;
pub const WINDIVERT_FLAG_FRAGMENTS: u64 = 0x0020;
pub const WINDIVERT_PARAM_QUEUE_LENGTH: u32 = 0;
pub const WINDIVERT_PARAM_QUEUE_TIME: u32 = 1;
pub const WINDIVERT_PARAM_QUEUE_SIZE: u32 = 2;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WinDivertAddress {
    pub timestamp: i64,
    pub flags_raw: u32,
    pub reserved2: u32,
    pub data: [u8; 64],
}

impl WinDivertAddress {
    pub const SERIALIZED_LEN: usize = 80;

    pub fn zeroed() -> Self {
        Self {
            timestamp: 0,
            flags_raw: 0,
            reserved2: 0,
            data: [0; 64],
        }
    }

    pub fn layer(&self) -> u8 { (self.flags_raw & 0xff) as u8 }
    pub fn is_outbound(&self) -> bool { (self.flags_raw >> 17) & 1 == 1 }
    pub fn is_loopback(&self) -> bool { (self.flags_raw >> 18) & 1 == 1 }
    pub fn is_impostor(&self) -> bool { (self.flags_raw >> 19) & 1 == 1 }
    pub fn interface_index(&self) -> u32 {
        u32::from_ne_bytes([self.data[0], self.data[1], self.data[2], self.data[3]])
    }

    pub fn to_bytes(&self) -> [u8; Self::SERIALIZED_LEN] {
        let mut bytes = [0u8; Self::SERIALIZED_LEN];
        bytes[0..8].copy_from_slice(&self.timestamp.to_ne_bytes());
        bytes[8..12].copy_from_slice(&self.flags_raw.to_ne_bytes());
        bytes[12..16].copy_from_slice(&self.reserved2.to_ne_bytes());
        bytes[16..80].copy_from_slice(&self.data);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::SERIALIZED_LEN {
            return None;
        }

        let mut data = [0u8; 64];
        data.copy_from_slice(&bytes[16..80]);

        Some(Self {
            timestamp: i64::from_ne_bytes(bytes[0..8].try_into().ok()?),
            flags_raw: u32::from_ne_bytes(bytes[8..12].try_into().ok()?),
            reserved2: u32::from_ne_bytes(bytes[12..16].try_into().ok()?),
            data,
        })
    }
}

#[cfg(windows)]
mod native {
    use super::*;
    use std::os::raw::c_void;

    type OpenFn = unsafe extern "system" fn(*const c_char, u8, i16, u64) -> *mut c_void;
    type RecvFn = unsafe extern "system" fn(*mut c_void, *mut u8, u32, *mut u32, *mut WinDivertAddress) -> i32;
    type SendFn = unsafe extern "system" fn(*mut c_void, *const u8, u32, *mut u32, *const WinDivertAddress) -> i32;
    type CloseFn = unsafe extern "system" fn(*mut c_void) -> i32;
    type SetParamFn = unsafe extern "system" fn(*mut c_void, u32, u64) -> i32;
    type GetParamFn = unsafe extern "system" fn(*mut c_void, u32, *mut u64) -> i32;
    type ChecksumsFn = unsafe extern "system" fn(*mut u8, u32, *mut WinDivertAddress, u64) -> i32;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LoadLibraryExW(name: *const u16, file: *mut c_void, flags: u32) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    }

    const LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: u32 = 0x0000_0100;

    pub struct Api {
        _module: *mut c_void,
        pub open: OpenFn,
        pub recv: RecvFn,
        pub send: SendFn,
        pub close: CloseFn,
        pub set_param: SetParamFn,
        pub get_param: GetParamFn,
        pub checksums: ChecksumsFn,
    }

    // SAFETY:
    // `Api` holds only:
    //   - a raw module handle (`*mut c_void`) that is never mutated after load
    //   - function pointers, which are inherently `Send + Sync`
    //
    // The WinDivert native API is designed to be called from multiple threads
    // (open/recv/send/close are all thread-safe per WinDivert documentation).
    // No thread-local state is stored in `Api`.
    unsafe impl Send for Api {}
    unsafe impl Sync for Api {}

    unsafe fn symbol<T>(module: *mut c_void, name: &'static [u8]) -> Result<T, String> {
        let p = GetProcAddress(module, name.as_ptr());
        if p.is_null() {
            return Err(format!("missing WinDivert export {}", String::from_utf8_lossy(&name[..name.len()-1])));
        }
        Ok(std::mem::transmute_copy(&p))
    }

    impl Api {
        fn load() -> Result<Self, String> {
            let path = super::local_dll("WinDivert.dll")
                .ok_or_else(|| "WinDivert.dll not found under packaged native runtime locations".to_string())?;
            let wide: Vec<u16> = path
                .as_os_str()
                .to_string_lossy()
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let module = unsafe {
                LoadLibraryExW(
                    wide.as_ptr(),
                    std::ptr::null_mut(),
                    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
                )
            };
            if module.is_null() {
                return Err(format!("failed to load {}", path.display()));
            }
            unsafe {
                Ok(Self {
                    _module: module,
                    open: symbol(module, b"WinDivertOpen\0")?,
                    recv: symbol(module, b"WinDivertRecv\0")?,
                    send: symbol(module, b"WinDivertSend\0")?,
                    close: symbol(module, b"WinDivertClose\0")?,
                    set_param: symbol(module, b"WinDivertSetParam\0")?,
                    get_param: symbol(module, b"WinDivertGetParam\0")?,
                    checksums: symbol(module, b"WinDivertHelperCalcChecksums\0")?,
                })
            }
        }
    }

    static API: std::sync::OnceLock<Result<Api, String>> = std::sync::OnceLock::new();
    pub fn get() -> Option<&'static Api> { API.get_or_init(Api::load).as_ref().ok() }
}

#[cfg(windows)]
fn local_dll(name: &str) -> Option<std::path::PathBuf> {
    let mut paths = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(p) = exe.parent() {
            paths.push(p.join(name));
            paths.push(p.join("native").join("windivert").join("runtime").join(name));
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        paths.push(cwd.join(name));
        paths.push(cwd.join("native").join("windivert").join("runtime").join(name));
    }
    paths.into_iter().find(|p| p.is_file())
}

#[cfg(windows)]
pub unsafe fn WinDivertOpen(a: *const c_char, b: u8, c: i16, d: u64) -> *mut c_void { native::get().map(|x| (x.open)(a, b, c, d)).unwrap_or(std::ptr::null_mut()) }
#[cfg(windows)]
pub unsafe fn WinDivertRecv(a: *mut c_void, b: *mut u8, c: u32, d: *mut u32, e: *mut WinDivertAddress) -> i32 { native::get().map(|x| (x.recv)(a, b, c, d, e)).unwrap_or(0) }
#[cfg(windows)]
pub unsafe fn WinDivertSend(a: *mut c_void, b: *const u8, c: u32, d: *mut u32, e: *const WinDivertAddress) -> i32 { native::get().map(|x| (x.send)(a, b, c, d, e)).unwrap_or(0) }
#[cfg(windows)]
pub unsafe fn WinDivertClose(a: *mut c_void) -> i32 { native::get().map(|x| (x.close)(a)).unwrap_or(0) }
#[cfg(windows)]
pub unsafe fn WinDivertSetParam(a: *mut c_void, b: u32, c: u64) -> i32 { native::get().map(|x| (x.set_param)(a, b, c)).unwrap_or(0) }
#[cfg(windows)]
pub unsafe fn WinDivertGetParam(a: *mut c_void, b: u32, c: *mut u64) -> i32 { native::get().map(|x| (x.get_param)(a, b, c)).unwrap_or(0) }
#[cfg(windows)]
pub unsafe fn WinDivertHelperCalcChecksums(a: *mut u8, b: u32, c: *mut WinDivertAddress, d: u64) -> i32 { native::get().map(|x| (x.checksums)(a, b, c, d)).unwrap_or(0) }

#[cfg(not(windows))]
pub unsafe fn WinDivertOpen(_: *const c_char, _: u8, _: i16, _: u64) -> *mut c_void { std::ptr::null_mut() }
#[cfg(not(windows))]
pub unsafe fn WinDivertRecv(_: *mut c_void, _: *mut u8, _: u32, _: *mut u32, _: *mut WinDivertAddress) -> i32 { 0 }
#[cfg(not(windows))]
pub unsafe fn WinDivertSend(_: *mut c_void, _: *const u8, _: u32, _: *mut u32, _: *const WinDivertAddress) -> i32 { 0 }
#[cfg(not(windows))]
pub unsafe fn WinDivertClose(_: *mut c_void) -> i32 { 1 }
#[cfg(not(windows))]
pub unsafe fn WinDivertSetParam(_: *mut c_void, _: u32, _: u64) -> i32 { 0 }
#[cfg(not(windows))]
pub unsafe fn WinDivertGetParam(_: *mut c_void, _: u32, _: *mut u64) -> i32 { 0 }
#[cfg(not(windows))]
pub unsafe fn WinDivertHelperCalcChecksums(_: *mut u8, _: u32, _: *mut WinDivertAddress, _: u64) -> i32 { 0 }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterError { Empty, EmbeddedNul }

pub fn validate_filter(filter: &str) -> Result<(), FilterError> {
    if filter.trim().is_empty() { Err(FilterError::Empty) }
    else if filter.contains('\0') { Err(FilterError::EmbeddedNul) }
    else { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn rejects_empty_filter() { assert_eq!(validate_filter(""), Err(FilterError::Empty)); assert_eq!(validate_filter("   "), Err(FilterError::Empty)); }
    #[test] fn rejects_filter_with_embedded_nul() { assert_eq!(validate_filter("true\0"), Err(FilterError::EmbeddedNul)); }
    #[test] fn accepts_reasonable_filter() { assert!(validate_filter("outbound and tcp").is_ok()); }
    #[test] fn address_layout_has_expected_size() { assert_eq!(std::mem::size_of::<WinDivertAddress>(), 80); assert_eq!(WinDivertAddress::SERIALIZED_LEN, 80); }
    #[test] fn address_roundtrip_preserves_all_fields() { let mut a = WinDivertAddress::zeroed(); a.timestamp = -123; a.flags_raw = 1 << 17; a.reserved2 = 55; a.data[0..4].copy_from_slice(&7u32.to_ne_bytes()); a.data[63] = 0xaa; let encoded = a.to_bytes(); let decoded = WinDivertAddress::from_bytes(&encoded).unwrap(); assert_eq!(decoded, a); }
    #[test] fn rejects_wrong_context_size() { assert!(WinDivertAddress::from_bytes(&[0; 79]).is_none()); assert!(WinDivertAddress::from_bytes(&[0; 81]).is_none()); }
    #[test] fn address_decodes_flags() { let mut a = WinDivertAddress::zeroed(); a.flags_raw = 1 << 17; assert!(a.is_outbound()); assert!(!a.is_loopback()); assert_eq!(a.layer(), 0); }
    #[test] fn address_reads_interface_index() { let mut a = WinDivertAddress::zeroed(); a.data[0..4].copy_from_slice(&7u32.to_ne_bytes()); assert_eq!(a.interface_index(), 7); }
}