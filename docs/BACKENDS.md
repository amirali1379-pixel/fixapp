# Network Engine — Backend Architecture

This document defines the ownership boundary between `network-engine.dll` and the native backends.

## 1. Ownership model

```text
HOST
  = policy / configuration authority

network-engine.dll
  = runtime owner + processor + orchestrator

BACKEND
  = native capability provider

PACKET BUS
  = observation transport
```

Backends must never become independent packet databases, flow engines, correlation engines, metadata engines, or Host-facing APIs.

## 2. Backends

### WFP

Provides WFP-specific filtering, layers, providers, flow information, policy metadata, and network-stack observations. WFP state remains owned by the WFP backend while normalized observations and Engine-level state remain owned by the Engine.

### WinDivert

Provides IP-layer interception, filtering, inspection, direction metadata, modification, drop/pass decisions, reinjection, queue control, and native error reporting.

### Npcap

Provides Layer-2/Ethernet capture, adapter discovery, MAC/interface information, and raw packet acquisition. Npcap observations enter the common `PacketObservation` model.

### IP Helper

Provides Windows network-state information: interfaces, addresses, routes, gateways, neighbors, and connection tables. It is an information backend, not an independent packet-processing pipeline.

### ETW

Provides diagnostics, telemetry, performance information, Windows networking events, and troubleshooting data. ETW must not become authoritative packet state.

## 3. Common observation contract

Packet-producing backends convert native observations into the Engine's `PacketObservation` model before entering the Packet Bus.

Required provenance includes:

- observation ID
- backend source
- capture timestamp
- ingestion timestamp
- direction
- interface identity
- packet length
- authoritative raw packet
- normalized native metadata
- optional opaque native action context

Raw packet data remains authoritative in the Engine.

## 4. Backend lifecycle

Every backend follows:

```text
Created -> Starting -> Running -> Degraded -> Failed
                         |             |
                         v             v
                      Stopping <----- Stopping
                         |
                         v
                       Stopped
```

A backend failure must be isolated. The Backend Manager reports health and capability state and may select another backend where the requested capability is available.

## 5. Capability negotiation

The Engine must check capability availability before executing an action. A missing native capability is reported as a controlled error rather than silently falling back to an incompatible operation.

## 6. Prohibited architecture

A backend must not:

- expose a Rust ABI to the Host;
- own the global packet lifecycle;
- persist authoritative packet copies;
- independently track global flows;
- perform cross-backend correlation;
- invent Host Gateway/NAT/routing policy;
- bypass the Engine's bounded queues;
- leak native handles across the public C ABI.

## 7. Release rule

The development tree may contain multiple Rust crates and backend integrations. The public product boundary remains `network-engine.dll`. Backend runtime files are shipped only when required by the selected release configuration.