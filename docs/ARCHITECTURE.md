# Network Engine — Architecture

## Product

`network-engine.dll` — a unified Windows network engine for Windows 10/11 x64,
written in Rust. The DLL is the **only** public product. All other crates are
internal implementation units.

## Layering

```
Host (C/C++/any language)
  │  stable C ABI (extern "C", no Rust types cross the boundary)
  ▼
FFI boundary (crates/ffi)          — ABI contracts only; owns NO engine logic
  ▼
Engine runtime (dll/network-engine) — orchestrator; owns all runtime state
  ▼
Internal crates                     — single-responsibility implementation units
  ▼
Backend capability providers        — native Windows capabilities only
```

## Ownership model

Packet observations move through explicit ownership states
(`network_core::ownership`):

```
Allocated → BackendOwned → EngineOwned → BusOwned → ProcessingOwned
         → HostOwned → Released
```

Ownership transfer is tracked by the Packet Bus. Double release,
use-after-release and duplicate ownership are prevented structurally.
The raw packet bytes in every observation remain **authoritative** from
capture to release; no layer mutates them in place.

## Data plane (hot path)

```
Backend receive
  → Timestamp (ingestion stamped; capture timestamp preserved)
  → Minimal validation (non-empty, length-consistent)
  → Buffer ownership transfer
  → PacketObservation → Packet Bus (bounded MPMC queue)
  → Processing pipeline:
       Parser → Correlation (dedup + flow identity) → Flow table
       → Metadata scheduling (async workers, off hot path)
       → Host-directed action → Backend action
```

Hot-path guarantees: no DNS, no database, no heavy logging, no blocking
operations. Queue-full is **reported** (observable saturation statistic +
`QueueFull` error), never silently dropped.

## Control plane

- **Host** is the policy/configuration/command authority.
- Packet actions (pass / drop / modify / reinject) are Host-directed only.
- Gateway config/start/stop are explicit Host commands.
- Backend lifecycle (start/stop/restart/health/failover) is Engine-controlled.

## Diagnostics plane

- ETW backend (`backend-etw`) is diagnostics-only.
- ETW failures degrade diagnostics only; they never block capture, the
  Packet Bus, forwarding or Gateway processing.

## Backend capability model

Each backend advertises a capability set (`network_core::capability`):
Capture, Interception, Filtering, Inspection, Direction, Layer2/3/4,
IPv4/IPv6, Modification, Pass, Drop, Reinjection, QueueControl,
AddressMetadata. Capability status: Available / Unavailable / Degraded /
Conditional.

Backends:

| Backend | Role |
|---|---|
| `backend-wfp` | first-class filtering/interception backend |
| `backend-windivert` | user-space packet interception & reinjection |
| `backend-npcap` | specialized Layer-2/raw capture provider |
| `backend-iphelper` | normalized Windows network state only (no interception) |
| `backend-etw` | diagnostics only |

Rules:

- Capability checks happen **before** capability-dependent actions.
- Failover only occurs to a backend with a technically sufficient
  capability. No forced failover on incompatible capabilities.
- Backend failure does not automatically terminate the Engine.
- A backend can never directly control another backend.

## Gateway capability

Gateway is **internal Engine functionality**. It is:

- NOT a backend
- NOT an autonomous router
- NOT autonomous NAT
- NOT autonomous forwarding

All Gateway/NAT/routing/forwarding **policy** belongs to the Host. All
Gateway/NAT **runtime state** belongs to the Engine. Forwarding occurs
only when Host-requested configuration enables it. NetworkState
represents Windows state and never automatically activates Gateway
behavior.

## NetworkState

`network-state` provides a coherent cached representation of interfaces,
addresses, routes, neighbors and gateways, normalized from the Windows
IP Helper API by `backend-iphelper`. It is informational and
authoritative about Windows state; it is not a routing engine.

## Failure model

- Bounded queues, flow tables, NAT state, DNS cache and dedup state —
  all pressure is observable.
- Missing optional metadata becomes `UNKNOWN`; it never forces packet loss.
- Drop categories are always distinct: `HostRequestedDrop`,
  `SafetyErrorDrop`, `BackendFailure`. There is no generic drops counter.
- Shutdown resolves ownership before releasing resources; no leaked
  threads, handles, callbacks or buffers.

## Lifecycle

```
Uninitialized → network_init → Running → network_shutdown → Shutdown
```

Initialization validates Host config, creates the Engine, initializes
the Packet Bus and NetworkState, discovers capabilities, initializes
requested backends and validates required capabilities. Gateway never
starts automatically. Shutdown follows the ordered sequence: stop new
operations → stop Gateway → stop capture → resolve packet ownership →
stop workers → stop backends → release native resources → release
Engine state.
