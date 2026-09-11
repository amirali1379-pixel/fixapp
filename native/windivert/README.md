# WinDivert native assets

This directory contains the WinDivert build/runtime assets consumed by `backend-windivert`.

- `lib/WinDivert.lib` is retained as the native import-library asset.
- `runtime/WinDivert.dll` and `runtime/WinDivert.sys` are the existing runtime/driver assets from the repository.
- The Rust FFI is defined in `crates/backend-windivert/src/ffi.rs` and dynamically resolves the DLL from the packaged `native/windivert/runtime` location.

The backend implementation is in `crates/backend-windivert`.
