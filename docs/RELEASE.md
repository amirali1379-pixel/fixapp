# Network Engine — Release Packaging

## Release artifact

Every release centers on exactly one binary:

```
network-engine.dll        (x64, Windows 10/11)
```

Built from the `dll/network-engine` crate (`crate-type = ["cdylib", "staticlib"]`)
with the workspace release profile: LTO enabled, single codegen unit,
stripped, `panic = "abort"`.

## Include in the release package

Only runtime-required components:

- `network-engine.dll`
- required third-party runtime DLLs, if any backend binding links them
  dynamically (e.g. WinDivert runtime DLL when the WinDivert backend is
  shipped enabled, Npcap runtime DLL when the Npcap backend is shipped
  enabled)
- required driver / install components for the enabled packet
  backends (e.g. the WinDivert driver package, the Npcap driver — only
  for backends actually shipped)
- required runtime configuration / data files (e.g. filter definitions,
  ETW manifest if diagnostics shipping requires it)

## Do NOT ship

- Cargo files (`Cargo.toml`, `Cargo.lock`)
- Rust source code (`src/`, `crates/`, `dll/`)
- Debug artifacts (`.pdb` when stripped releases are policy, `.d` files,
  incremental caches)
- Unused backend binaries (e.g. Npcap driver when only WFP is enabled)
- Development scripts, benches, test harnesses
- Documentation sources not intended for end users

Native Windows system components (kernel32, ntdll, ws2_32, iphlpapi,
fwpuclnt, etc.) must NOT be copied into the package merely because they
exist in the development environment. They are part of Windows.

## Versioning

- ABI stability: the C ABI documented in `docs/API.md` is stable within
  a major version. Breaking ABI changes require a major version bump.
- DLL version resource should match the release version.

## Pre-release checklist

1. `cargo fmt --all -- --check` — clean
2. `cargo clippy --workspace --all-targets` — no warnings
3. `cargo build --release -p network-engine` — succeeds for
   `x86_64-pc-windows-msvc` (or `-gnu`)
4. On supported Windows x64: native integration validation, ABI
   validation, lifecycle validation, backend validation
5. Verify the package contains ONLY the items listed under "Include"
6. Verify drop-category statistics remain distinct in the shipped build
   (no aggregated drops counter)

## Expected invariants for every release

- 0 compile errors
- no ABI violations
- no ownership violations
- no unbounded queues/state
- no arbitrary Engine-generated DROP
