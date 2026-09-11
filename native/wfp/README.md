# WFP native assets

This directory contains the WFP build/runtime assets used by the workspace.

- `lib/fwpuclnt.lib` is the Windows import library used by the `backend-wfp` build.
- WFP is accessed from Rust through `windows-sys`; this repository does not maintain a local copy of `fwpmu.h`.
- Windows system components such as the installed WFP client DLL/driver are not treated as application-owned runtime payloads.

The backend implementation is in `crates/backend-wfp`.
