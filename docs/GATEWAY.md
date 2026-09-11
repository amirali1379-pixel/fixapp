# Network Engine — Gateway Capability

## Scope

`network-engine.dll` is gateway-capable, but it is not an autonomous Gateway service. The Host owns Gateway, NAT, routing, forwarding, filtering, and lifecycle policy.

## Runtime flow

```text
HOST POLICY
   |
   v
network-engine.dll
   |
   +--> validate interfaces/routes/neighbors
   +--> negotiate backend capabilities
   +--> maintain connection/NAT state
   +--> process ingress packet
   +--> route / forward according to Host policy
   +--> execute backend packet action
   +--> process egress packet
```

## Ingress / egress

Ingress processing validates packet ownership and parsing before a forwarding decision. Egress processing selects the configured interface and executes only a capability supported by the active backend.

The original observation remains authoritative. Derived routing, NAT, and connection state must never replace raw packet ownership.

## NAT

NAT is an Engine capability. The Host supplies NAT policy and interface configuration. The Engine maintains translation state, reverse lookup information, timeout state, and packet/action association. The Engine must never silently enable NAT.

## Routing

The Engine may consume normalized route state and perform route lookup required by an explicitly configured policy. It must not silently modify the Windows routing table or invent routes.

## Forwarding

Forwarding requires the capabilities needed to execute the requested action, including reinjection where applicable, route information, and neighbor information. If a required capability is unavailable, forwarding must fail closed with a controlled capability error.

## Connection continuity

Gateway processing should preserve flow identity across ingress and egress. NAT/state entries require bounded lifetime and deterministic cleanup. Backend failover must not create duplicate authoritative flow state.

## Failure rules

- Invalid Gateway policy is rejected before activation.
- Missing interfaces/routes/neighbors cause capability errors.
- Backend failure is isolated by Backend Manager.
- Queue saturation must remain bounded; packets are never accepted into an unbounded emergency queue.
- Shutdown must stop Gateway processing before releasing Engine-owned packet state.

## Public boundary

Only the C ABI is exposed to the Host. Internal Rust Gateway types remain implementation details of `network-engine.dll`.