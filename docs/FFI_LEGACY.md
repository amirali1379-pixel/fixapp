# Legacy FFI implementation decision

The workspace `crates/ffi` crate is now the public C ABI contract crate. Its compiled surface is intentionally limited to:

- `types.rs`
- `handles.rs`
- `errors.rs`
- `validation.rs`

The older implementation modules under `crates/ffi/src/` are retained as migration/reference history and are **not compiled** by `crates/ffi/src/lib.rs`.

In particular, `crates/ffi/src/api.rs` is legacy implementation code. It is not part of the public DLL runtime and is not imported by the current FFI crate. The runtime-owned ABI exports live in `dll/network-engine/src/ffi_exports.rs` and `dll/network-engine/src/ffi_backend.rs`.

## Decision

Keep the legacy implementation files for now rather than deleting them. This preserves migration history while preventing them from becoming a second runtime or ABI implementation.

Any future reuse of code from these files must be reviewed and moved into the owning DLL/runtime or ABI-contract module explicitly. The legacy modules must not be re-enabled by adding them back to `crates/ffi/src/lib.rs`.
