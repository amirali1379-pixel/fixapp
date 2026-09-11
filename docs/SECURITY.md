# Network Engine — Security and Robustness

## Security boundary

The public attack surface is the C ABI and native backend integration. Rust internals remain behind the DLL boundary.

## FFI validation

Every pointer and length pair must be validated before dereference. Integer conversions must be checked before narrowing. Output buffers require explicit capacity validation and NUL termination. No Rust-owned `String`, `Vec`, slice, enum layout, trait object, or backend-native type crosses the ABI.

## Required tests

### Integer safety

- oversized packet lengths
- `u64 -> u32` handle/length conversions
- queue/pool capacity overflow
- flow counters near maximum values
- timestamp arithmetic overflow

### Pointer and buffer safety

- null input/output pointers
- zero-length buffers
- insufficient output capacity
- invalid UTF-8 strings
- stale/released packet handles
- handle collision and restoration paths

### Concurrency

- simultaneous backend shutdown and packet processing
- shutdown while producers are blocked on a full queue
- shutdown while consumers wait on an empty queue
- concurrent packet-handle release
- concurrent backend health transitions

### Backend failure

- initialization failure
- runtime backend failure
- degraded backend
- native action failure
- backend recovery/restart
- cleanup after panic or unexpected termination

## Fail-closed rules

A capability that cannot be verified must not be treated as available. Forwarding and reinjection must not continue after a required backend capability is lost.

## Resource cleanup

All Engine-owned packet handles, queue entries, backend handles, worker threads, and native resources must have deterministic cleanup paths. Shutdown must be safe to retry when a previous shutdown attempt fails.

## Security acceptance

Release validation must include malformed packets for every parser, ABI fuzz-style boundary cases, queue saturation, backend restart, and Windows x64 native build verification.