//! Process-level native dependency setup.
//!
//! Third-party capture libraries (WinDivert, npcap) are packaged directly
//! alongside `network_engine.dll` — see `scripts/package-windows.ps1`, which
//! copies `WinDivert.dll`, `WinDivert.sys`, `wpcap.dll` and `Packet.dll` into
//! the same output directory as the DLL itself (no separate `lib/` bundle).
//! Because those libraries are linked with `/DELAYLOAD`, Windows only
//! resolves them on first use, so this must run during initialization —
//! before any backend touches WinDivert/npcap — never on the packet hot path.

#[cfg(windows)]
use std::path::PathBuf;

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn SetDllDirectoryW(path: *const u16) -> i32;
    fn GetModuleHandleExW(flags: u32, module_name: *const u16, module: *mut isize) -> i32;
    fn GetModuleFileNameW(module: isize, buffer: *mut u16, size: u32) -> u32;
}

#[cfg(windows)]
const GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS: u32 = 0x0000_0004;

/// Resolves the directory that `network_engine.dll` itself was loaded from,
/// by asking Windows which module owns the address of this very function.
/// This is the directory the packaging script actually populates, and it is
/// correct regardless of where the host application's .exe lives.
#[cfg(windows)]
fn own_module_directory() -> Option<PathBuf> {
    unsafe {
        let mut module: isize = 0;
        let anchor = own_module_directory as usize as *const u16;
        if GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, anchor, &mut module) == 0 {
            return None;
        }

        let mut buffer = vec![0u16; 32768];
        let len = GetModuleFileNameW(module, buffer.as_mut_ptr(), buffer.len() as u32);
        if len == 0 {
            return None;
        }
        buffer.truncate(len as usize);

        PathBuf::from(String::from_utf16_lossy(&buffer))
            .parent()
            .map(|p| p.to_path_buf())
    }
}

#[cfg(windows)]
pub fn prepare() -> Result<(), &'static str> {
    let mut candidates = Vec::<PathBuf>::new();

    // Preferred: wherever network_engine.dll itself was loaded from — this
    // matches scripts/package-windows.ps1's actual output layout.
    if let Some(dir) = own_module_directory() {
        candidates.push(dir);
    }

    // Fallback: next to the host application's executable.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidates.push(parent.to_path_buf());
        }
    }

    // Last resort: current working directory.
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd);
    }

    let native_dir = candidates
        .into_iter()
        .find(|path| path.is_dir())
        .ok_or("could not resolve a directory containing the native runtime DLLs")?;

    let wide: Vec<u16> = native_dir
        .as_os_str()
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let result = unsafe { SetDllDirectoryW(wide.as_ptr()) };
    if result == 0 {
        return Err("Windows rejected the native runtime directory");
    }

    Ok(())
}

#[cfg(not(windows))]
pub fn prepare() -> Result<(), &'static str> {
    Ok(())
}
