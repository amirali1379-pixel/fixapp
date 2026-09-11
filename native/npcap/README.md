# Npcap native assets

This directory contains the Npcap build/runtime assets consumed by `backend-npcap`.

- `lib/wpcap.lib` and `lib/Packet.lib` are link-time inputs.
- `runtime/wpcap.dll` and `runtime/Packet.dll` are runtime payloads copied by the Windows packaging script when Npcap is selected.
- The Rust FFI declarations live in `crates/backend-npcap/src/ffi.rs`; no local Npcap SDK header is duplicated here.

The backend implementation is in `crates/backend-npcap`.
