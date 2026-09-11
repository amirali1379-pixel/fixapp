// crates/backend-manager/src/lib.rs

#![forbid(unsafe_code)]

// Backend Manager owns backend registration, lifecycle, health, capability
// inventory, failover coordination, backend complementarity, and
// deterministic backend selection.
//
// Native execution and Host policy remain outside this crate.

mod backend;
mod capabilities;
mod complementarity;
mod failover;
mod health;
mod manager;
mod registry;
mod selection;
mod state;

pub use backend::{
    BackendDescriptor,
    BackendLifecycle,
    BackendRole,
    BackendRuntimeState,
};

pub use capabilities::{
    check_requirements,
    BackendCapability,
    CapabilityCheck,
    CapabilityRequirement,
    CapabilitySet,
};

pub use complementarity::{
    capability_status,
    select_with_fallback,
    CapabilityCoverage,
    CapabilityFallbackMatrix,
    CapabilityStatus,
};

pub use failover::{
    FailoverBackend,
    FailoverError,
    FailoverManager,
    FailoverState,
};

pub use health::{
    BackendHealth,
    HealthMonitor,
};

pub use manager::{
    BackendManager,
    BackendManagerStats,
    FailoverPolicy,
};

pub use registry::CapabilityRegistry;

pub use selection::{
    find_capable_requirements,
    find_healthy_capable_requirements,
    select_backend_for_requirements,
    select_healthy_backend_for_failover,
};