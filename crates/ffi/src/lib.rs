// crates/ffi/src/lib.rs
//
// network-engine.dll — public C ABI + Engine runtime.
//
// This crate is the single owner of:
//   - the stable C ABI boundary (`api`)
//   - the Engine runtime (`engine` and its lifecycle/pipeline modules)
//   - the ABI contract types (`types`, `handles`, `errors`, `validation`)
//
// The final `dll/network-engine` crate is a thin wrapper that re-exports
// this crate and compiles the cdylib.
//
// # Safety
//
// This crate is the only place in the project where `unsafe` is
// permitted, because the C ABI boundary is intrinsically unsafe.
// Every `unsafe` block must be justified by an FFI boundary.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(unsafe_code)]

// ─────────────────────────────────────────────────────────────────────
// ABI contract modules
// ─────────────────────────────────────────────────────────────────────

pub mod types;
pub mod handles;
pub mod errors;
pub mod validation;

pub use types::*;
pub use handles::*;
pub use errors::*;
pub use validation::*;

// ─────────────────────────────────────────────────────────────────────
// Runtime modules
// ─────────────────────────────────────────────────────────────────────

mod engine;
mod init;
mod capture;
mod processing;
mod gateway;
mod statistics;
mod backends;
mod backend_defaults;
mod coordination;
mod load_balancer;
mod metrics;
mod shutdown;

// Legacy modules preserved from the previous architecture.
//
// These are kept as-is and are not part of the active C ABI surface.
// They remain reachable in Rust so that existing callers and tests
// continue to compile.
mod backend_runtime;
mod capture_api;
mod decision;
mod native_runtime;
mod policy_api;

// ─────────────────────────────────────────────────────────────────────
// C ABI exports
// ─────────────────────────────────────────────────────────────────────

mod api;
mod ffi_backend;

pub use api::*;
pub use ffi_backend::*;

// ─────────────────────────────────────────────────────────────────────
// Runtime re-exports
// ─────────────────────────────────────────────────────────────────────

pub use engine::EngineRuntime;
pub use init::EngineConfig;
pub use statistics::UnifiedStatisticsSnapshot;
pub use coordination::{
    CapabilityCoverageSummary,
    CoordinatedObservation,
    MultiBackendCoordinator,
};
pub use load_balancer::{
    BackendLoad,
    LoadBalancer,
    LoadBalancerStats,
    LoadDecision,
    WorkKind,
};
pub use metrics::MetricsView;

// ─────────────────────────────────────────────────────────────────────
// Backend provider linkage
// ─────────────────────────────────────────────────────────────────────

use backend_etw;
use backend_iphelper;
use backend_npcap;
use backend_wfp;
use backend_windivert;

use backend_contracts;
use backend_manager;
use correlation;
use flow_engine;
use gateway_capability;
use metadata_engine;
use network_core;
use network_state;
use packet_bus;
use packet_parser;