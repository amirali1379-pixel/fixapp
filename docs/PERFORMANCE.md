# Network Engine — Performance Plan

## Goals

Measure the latency and bounded-resource behavior of the complete Engine rather than optimizing isolated functions without end-to-end evidence.

## Required benchmarks

| Benchmark | Measurement |
|---|---|
| capture latency | backend receive/observation timestamp -> Packet Bus ingestion |
| queue latency | Packet Bus enqueue -> dequeue under controlled load |
| correlation latency | observation arrival -> correlation result |
| gateway/forwarding latency | ingress -> routing -> egress action completion |
| metadata latency | packet/flow event -> metadata/cache result |
| parser latency | existing parser microbenchmark |
| flow-table latency | existing flow-table microbenchmark |
| buffer-pool latency | existing buffer-pool microbenchmark |

## Method

Each benchmark must report at least:

- iterations
- warm-up iterations
- median
- p95
- p99
- maximum
- throughput where meaningful
- packet size / flow count / queue capacity
- CPU architecture and Rust toolchain
- Windows version for native benchmarks

Native backend benchmarks must be clearly separated from pure-Rust microbenchmarks.

## Acceptance principles

1. No benchmark may hide packet drops or queue-full results.
2. Queue capacity must remain bounded during load tests.
3. Results must be reproducible on the same Windows x64 environment.
4. Optimization must not change packet ownership semantics or the C ABI.
5. Hot-path benchmarks must avoid unrelated logging and disk I/O.

## Reporting

Benchmark results belong in a versioned report with the exact commit SHA and environment. Do not claim a performance target is met without a real Windows x64 run.

## Current implementation status

The repository currently contains Criterion benchmarks for packet parsing, flow-table operations, and buffer-pool operations. Additional benchmark targets are required for capture, queue, correlation, Gateway/forwarding, and metadata latency.