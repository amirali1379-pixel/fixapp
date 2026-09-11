# Network Engine — Stable C ABI

`network-engine.dll` is the only Host-facing binary interface. The Host must use the C ABI and must not depend on internal Rust crates or backend implementation types.

## ABI rules

- All exported functions use `extern "C"` and C-compatible scalar/pointer types.
- Public structs use C-compatible layouts.
- Packet handles are engine-owned `uint64_t` values; `0` is invalid.
- Packet descriptor memory is owned by the Engine and remains valid while its handle is retained.
- Every output buffer has an explicit capacity and is NUL-terminated on success.
- Return value `0` means success; negative values are `NE_ERROR_*`.
- No Rust `String`, `Vec`, slice, enum, trait object, or backend implementation type crosses the ABI.
- The Engine owns packet lifecycle and native action execution; the Host selects policy.

## Error codes

| Name | Value |
|---|---:|
| `NE_OK` | 0 |
| `NE_ERROR_INVALID_ARGUMENT` | -1 |
| `NE_ERROR_INVALID_HANDLE` | -2 |
| `NE_ERROR_NOT_INITIALIZED` | -3 |
| `NE_ERROR_ALREADY_INITIALIZED` | -4 |
| `NE_ERROR_BACKEND_UNAVAILABLE` | -5 |
| `NE_ERROR_QUEUE_FULL` | -6 |
| `NE_ERROR_BUFFER_EXHAUSTED` | -7 |
| `NE_ERROR_ACTION_FAILED` | -8 |
| `NE_ERROR_SHUTDOWN` | -9 |
| `NE_ERROR_INTERNAL` | -10 |

`last_error_message()` returns the most recent human-readable ABI error.

## Lifecycle

```c
int32_t network_init(const NeInitConfig *config);
int32_t network_shutdown(void);
int32_t network_is_initialized(void);
```

`NeInitConfig` contains `queue_capacity`, `pool_max_size`, `buffer_capacity`, and `max_flows`. All must be greater than zero.

Shutdown is transactional: the runtime remains owned by the DLL if shutdown fails, so the Host can retry. Packet handles are cleared only after successful shutdown.

Gateway processing is never started implicitly by `network_init`.

## Backend control

```c
uint32_t backend_count(void);
int32_t backend_list(char *buffer, uint32_t max_count, uint32_t name_len);
int32_t backend_status(const char *name);
int32_t backend_set_status(const char *name, int32_t status);
int32_t capability_check(const char *backend_name, int32_t capability);
```

Lifecycle values are stable numeric values:

```text
0 Disabled
1 Starting
2 Running
3 Degraded
4 Failed
5 Stopping
6 Stopped
```

Capability values use the stable `BackendCapability` discriminants documented in `dll/network-engine/include/network_engine.h`.

## Packet capture and ownership

```c
int32_t packet_inject(const void *data, uint32_t len,
                     int32_t backend_source, int32_t direction,
                     uint32_t interface_id);
int32_t packet_read(NePacketDescriptor *out);
int32_t packet_release(uint64_t packet_handle);
```

`packet_read()` is non-blocking. An empty queue currently returns `NE_ERROR_QUEUE_FULL` because the existing ABI error set has no separate queue-empty code.

`packet_inject()` copies the supplied bytes into Engine-owned observation storage.

The Host must release every successful packet handle unless a terminal action consumes it.

## Packet actions

```c
int32_t packet_pass(uint64_t packet_handle);
int32_t packet_drop(uint64_t packet_handle);
int32_t packet_modify(uint64_t packet_handle,
                      const void *data, uint32_t len);
int32_t packet_reinject(uint64_t packet_handle);
int32_t packet_action(uint64_t packet_handle, int32_t action);
```

Actions are Host-directed. The original observation remains authoritative.

`packet_pass`, `packet_modify`, and `packet_reinject` are transactional: if native execution fails, the original packet handle is restored instead of being silently lost.

`packet_action(..., NE_PACKET_ACTION_MODIFY)` is intentionally rejected because modification requires the replacement payload and therefore must use `packet_modify()`.

## Statistics and flow state

```c
int32_t engine_statistics(NeStatistics *out);
uint32_t bus_queue_depth(void);
uint32_t bus_queue_capacity(void);
uint32_t pool_allocated_count(void);
uint32_t pool_available_count(void);
uint32_t flow_count(void);
int32_t flow_get(char *buffer, uint32_t capacity);
int32_t flow_stats(const char *key, uint64_t *packets, uint64_t *bytes);
uint32_t flow_clear_expired(void);
```

`NeStatistics` exposes received packets/bytes, aggregated dropped packets, forwarded packets, and active flows.

## Network state

```c
int32_t interface_list(char *buffer, uint32_t capacity);
int32_t interface_info(uint32_t interface_id,
                       char *buffer, uint32_t capacity);
int32_t route_list(char *buffer, uint32_t capacity);
int32_t neighbor_list(char *buffer, uint32_t capacity);
```

The current ABI returns JSON text in caller-provided buffers so Rust-specific state structures do not cross the boundary.

## Gateway

```c
int32_t gateway_config(const char *enabled);
int32_t gateway_start(void);
int32_t gateway_stop(void);
int32_t gateway_status(void);
```

The Host remains responsible for Gateway policy. The DLL executes capability checks and runtime state transitions; it does not invent routing, NAT, filtering, or forwarding policy.

## Diagnostics / version

```c
int32_t engine_version(char *buffer, uint32_t capacity);
int32_t last_error_message(char *buffer, uint32_t capacity);
```

## Public header

The canonical C/C++ declarations are provided in:

```text
dll/network-engine/include/network_engine.h
```

That header is the Host integration boundary. Internal Rust crates remain implementation details of `network-engine.dll`.
