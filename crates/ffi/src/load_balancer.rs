// crates/ffi/src/load_balancer.rs

//! Load Balancer for multi-backend packet processing.
//!
//! The Load Balancer is the Engine-managed component that distributes
//! work across the available backends so that:
//!
//! - No backend remains idle while others are saturated.
//! - No packet is dropped merely because one backend is overloaded.
//! - Each backend performs its specialized work.
//! - Backend Complementarity is respected.
//!
//! ## Scope
//!
//! The Load Balancer is a **decision layer**. It reports which backend
//! should handle a given unit of work and how much work is currently
//! pending on each backend.
//!
//! It does NOT:
//! - start, stop, or reconfigure native backends
//! - execute native operations
//! - transfer native contexts between backends
//! - fabricate capability availability
//! - modify raw packet data
//! - own global Engine policy
//!
//! Native execution remains the responsibility of the backends that
//! declare the capability.
//!
//! ## Data Source Rule
//!
//! The Load Balancer only queries the `BackendManager` (registered
//! backends + capabilities) and the current per-backend load counters.
//! It does not read from Windows host machine state.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use backend_manager::{
    BackendCapability,
    BackendHealth,
    BackendLifecycle,
    BackendManager,
};

/// Kind of work to be distributed across backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WorkKind {
    L2Observation,
    L3Capture,
    Filtering,
    Modification,
    Reinjection,
    Metadata,
    FlowInfo,
    NetworkState,
    Diagnostics,
}

impl WorkKind {
    /// Returns the primary capability required by this kind of work.
    pub const fn primary_capability(self) -> BackendCapability {
        match self {
            Self::L2Observation => BackendCapability::L2Capture,
            Self::L3Capture => BackendCapability::Capture,
            Self::Filtering => BackendCapability::Filtering,
            Self::Modification => BackendCapability::Modification,
            Self::Reinjection => BackendCapability::Reinjection,
            Self::Metadata => BackendCapability::WfpFlows,
            Self::FlowInfo => BackendCapability::WfpFlows,
            Self::NetworkState => BackendCapability::InterfaceInfo,
            Self::Diagnostics => BackendCapability::Diagnostics,
        }
    }

    /// Returns the fallback capability that can partially cover this kind
    /// of work when the primary capability is unavailable.
    pub const fn fallback_capability(self) -> Option<BackendCapability> {
        match self {
            Self::L2Observation => Some(BackendCapability::Capture),
            Self::L3Capture => Some(BackendCapability::L2Capture),
            Self::Filtering => Some(BackendCapability::Drop),
            Self::Modification => None,
            Self::Reinjection => None,
            Self::Metadata => Some(BackendCapability::WfpFlows),
            Self::FlowInfo => None,
            Self::NetworkState => Some(BackendCapability::NeighborInfo),
            Self::Diagnostics => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::L2Observation => "l2_observation",
            Self::L3Capture => "l3_capture",
            Self::Filtering => "filtering",
            Self::Modification => "modification",
            Self::Reinjection => "reinjection",
            Self::Metadata => "metadata",
            Self::FlowInfo => "flow_info",
            Self::NetworkState => "network_state",
            Self::Diagnostics => "diagnostics",
        }
    }
}

/// Runtime load snapshot of a single backend.
#[derive(Debug, Clone, Copy, Default)]
pub struct BackendLoad {
    pub in_flight: u64,
    pub completed: u64,
    pub saturated: u64,
    pub failed: u64,
}

impl BackendLoad {
    pub fn total(&self) -> u64 {
        self.completed
            .saturating_add(self.saturated)
            .saturating_add(self.failed)
    }

    pub fn is_idle(&self) -> bool {
        self.in_flight == 0
    }
}

/// Per-backend load counters (lock-free).
#[derive(Debug)]
struct BackendLoadCounters {
    in_flight: AtomicU64,
    completed: AtomicU64,
    saturated: AtomicU64,
    failed: AtomicU64,
}

impl BackendLoadCounters {
    fn new() -> Self {
        Self {
            in_flight: AtomicU64::new(0),
            completed: AtomicU64::new(0),
            saturated: AtomicU64::new(0),
            failed: AtomicU64::new(0),
        }
    }

    fn snapshot(&self) -> BackendLoad {
        BackendLoad {
            in_flight: self.in_flight.load(Ordering::Acquire),
            completed: self.completed.load(Ordering::Acquire),
            saturated: self.saturated.load(Ordering::Acquire),
            failed: self.failed.load(Ordering::Acquire),
        }
    }
}

/// Decision returned by the Load Balancer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadDecision {
    pub backend: Option<String>,
    pub capability: BackendCapability,
    pub used_fallback: bool,
}

impl LoadDecision {
    pub fn is_routed(&self) -> bool {
        self.backend.is_some()
    }
}

/// Aggregate Load Balancer statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct LoadBalancerStats {
    pub decisions: u64,
    pub fallback_decisions: u64,
    pub unrouted_decisions: u64,
    pub reported_saturated: u64,
    pub reported_completed: u64,
    pub reported_failed: u64,
}

/// The Load Balancer.
#[derive(Debug)]
pub struct LoadBalancer {
    manager: Arc<BackendManager>,
    counters: RwLock<HashMap<String, BackendLoadCounters>>,
    decisions: AtomicU64,
    fallback_decisions: AtomicU64,
    unrouted_decisions: AtomicU64,
    reported_saturated: AtomicU64,
    reported_completed: AtomicU64,
    reported_failed: AtomicU64,
}

impl LoadBalancer {
    pub fn new(manager: Arc<BackendManager>) -> Self {
        Self {
            manager,
            counters: RwLock::new(HashMap::new()),
            decisions: AtomicU64::new(0),
            fallback_decisions: AtomicU64::new(0),
            unrouted_decisions: AtomicU64::new(0),
            reported_saturated: AtomicU64::new(0),
            reported_completed: AtomicU64::new(0),
            reported_failed: AtomicU64::new(0),
        }
    }

    /// Chooses a backend for the requested work kind.
    pub fn select(&self, kind: WorkKind) -> LoadDecision {
        let primary = kind.primary_capability();
        let fallback = kind.fallback_capability();

        if let Some(name) = self.pick_backend_for_capability(primary) {
            self.decisions.fetch_add(1, Ordering::Relaxed);
            return LoadDecision {
                backend: Some(name),
                capability: primary,
                used_fallback: false,
            };
        }

        if let Some(capability) = fallback {
            if let Some(name) = self.pick_backend_for_capability(capability) {
                self.decisions.fetch_add(1, Ordering::Relaxed);
                self.fallback_decisions.fetch_add(1, Ordering::Relaxed);
                return LoadDecision {
                    backend: Some(name),
                    capability,
                    used_fallback: true,
                };
            }
        }

        self.decisions.fetch_add(1, Ordering::Relaxed);
        self.unrouted_decisions.fetch_add(1, Ordering::Relaxed);
        LoadDecision {
            backend: None,
            capability: primary,
            used_fallback: false,
        }
    }

    fn pick_backend_for_capability(
        &self,
        capability: BackendCapability,
    ) -> Option<String> {
        let candidates = self.manager.find_capable(capability);
        if candidates.is_empty() {
            return None;
        }

        let mut best: Option<(String, u64)> = None;

        for name in candidates {
            let runtime = match self.manager.runtime_state(&name) {
                Ok(runtime) => runtime,
                Err(_) => continue,
            };

            let lifecycle_ok = matches!(
                runtime.lifecycle,
                BackendLifecycle::Running | BackendLifecycle::Degraded
            );
            if !lifecycle_ok {
                continue;
            }

            let health_ok = match self.manager.health(&name) {
                Ok(health) => health != BackendHealth::Unhealthy,
                Err(_) => false,
            };
            if !health_ok {
                continue;
            }

            let load = self.load_of(&name).in_flight;

            match &best {
                None => best = Some((name, load)),
                Some((current_name, current_load)) => {
                    if load < *current_load {
                        best = Some((name, load));
                    } else if load == *current_load && name < *current_name {
                        best = Some((name, load));
                    }
                }
            }
        }

        best.map(|(name, _)| name)
    }

    /// Returns the current load of a backend.
    pub fn load_of(&self, backend: &str) -> BackendLoad {
        self.counters
            .read()
            .ok()
            .and_then(|map| map.get(backend).map(|c| c.snapshot()))
            .unwrap_or_default()
    }

    /// Returns a deterministic snapshot of all known backend loads.
    pub fn loads(&self) -> Vec<(String, BackendLoad)> {
        let Ok(map) = self.counters.read() else {
            return Vec::new();
        };

        let mut result: Vec<(String, BackendLoad)> = map
            .iter()
            .map(|(name, counters)| (name.clone(), counters.snapshot()))
            .collect();

        result.sort_by(|a, b| a.0.cmp(&b.0));
        result
    }

    /// Ensures a counters entry exists for the given backend.
    fn ensure_counters(&self, backend: &str) {
        if let Ok(mut map) = self.counters.write() {
            map.entry(backend.to_string())
                .or_insert_with(BackendLoadCounters::new);
        }
    }

    /// Applies an atomic update on the backend's counters while holding
    /// a read lock on the map.
    fn with_counters<F>(&self, backend: &str, f: F)
    where
        F: FnOnce(&BackendLoadCounters),
    {
        self.ensure_counters(backend);
        if let Ok(map) = self.counters.read() {
            if let Some(counters) = map.get(backend) {
                f(counters);
            }
        }
    }

    /// Records the start of a work item on a backend.
    pub fn report_started(&self, backend: &str) {
        self.with_counters(backend, |counters| {
            counters.in_flight.fetch_add(1, Ordering::AcqRel);
        });
    }

    /// Records the successful completion of a work item on a backend.
    pub fn report_completed(&self, backend: &str) {
        self.reported_completed.fetch_add(1, Ordering::Relaxed);
        self.with_counters(backend, |counters| {
            counters.in_flight.fetch_sub(
                counters.in_flight.load(Ordering::Acquire).min(1),
                Ordering::AcqRel,
            );
            counters.completed.fetch_add(1, Ordering::AcqRel);
        });
    }

    /// Records a saturated work item on a backend.
    pub fn report_saturated(&self, backend: &str) {
        self.reported_saturated.fetch_add(1, Ordering::Relaxed);
        self.with_counters(backend, |counters| {
            counters.in_flight.fetch_sub(
                counters.in_flight.load(Ordering::Acquire).min(1),
                Ordering::AcqRel,
            );
            counters.saturated.fetch_add(1, Ordering::AcqRel);
        });
    }

    /// Records a failed work item on a backend.
    pub fn report_failed(&self, backend: &str) {
        self.reported_failed.fetch_add(1, Ordering::Relaxed);
        self.with_counters(backend, |counters| {
            counters.in_flight.fetch_sub(
                counters.in_flight.load(Ordering::Acquire).min(1),
                Ordering::AcqRel,
            );
            counters.failed.fetch_add(1, Ordering::AcqRel);
        });
    }

    /// Removes a backend's load counters (used during backend shutdown).
    pub fn forget(&self, backend: &str) {
        if let Ok(mut map) = self.counters.write() {
            map.remove(backend);
        }
    }

    /// Returns an aggregate snapshot of the Load Balancer.
    pub fn stats(&self) -> LoadBalancerStats {
        LoadBalancerStats {
            decisions: self.decisions.load(Ordering::Relaxed),
            fallback_decisions: self.fallback_decisions.load(Ordering::Relaxed),
            unrouted_decisions: self.unrouted_decisions.load(Ordering::Relaxed),
            reported_saturated: self.reported_saturated.load(Ordering::Relaxed),
            reported_completed: self.reported_completed.load(Ordering::Relaxed),
            reported_failed: self.reported_failed.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use backend_manager::{BackendDescriptor, CapabilitySet};
    use packet_bus::PacketBus;

    fn descriptor(name: &str, capabilities: &[BackendCapability]) -> BackendDescriptor {
        BackendDescriptor::new(
            name,
            "0.1.0",
            "load balancer test backend",
            CapabilitySet::from(capabilities.iter().copied()),
        )
    }

    fn running(manager: &BackendManager, name: &str) {
        let bus = Arc::new(PacketBus::new(64));
        manager.start(name, bus).unwrap();
        manager.mark_running(name).unwrap();
    }

    #[test]
    fn selects_primary_backend_for_work_kind() {
        let manager = Arc::new(BackendManager::new());
        manager
            .register(descriptor("npcap", &[BackendCapability::L2Capture]))
            .unwrap();
        running(&manager, "npcap");

        let lb = LoadBalancer::new(manager);
        let decision = lb.select(WorkKind::L2Observation);

        assert!(decision.is_routed());
        assert_eq!(decision.backend.as_deref(), Some("npcap"));
        assert!(!decision.used_fallback);
    }

    #[test]
    fn selects_fallback_when_primary_unavailable() {
        let manager = Arc::new(BackendManager::new());
        manager
            .register(descriptor("windivert", &[BackendCapability::Capture]))
            .unwrap();
        running(&manager, "windivert");

        let lb = LoadBalancer::new(manager);
        let decision = lb.select(WorkKind::L2Observation);

        assert!(decision.is_routed());
        assert_eq!(decision.backend.as_deref(), Some("windivert"));
        assert!(decision.used_fallback);
    }

    #[test]
    fn reports_unrouted_when_no_backend_available() {
        let manager = Arc::new(BackendManager::new());
        let lb = LoadBalancer::new(manager);

        let decision = lb.select(WorkKind::Reinjection);

        assert!(!decision.is_routed());
        assert!(decision.backend.is_none());
    }

    #[test]
    fn prefers_least_loaded_backend() {
        let manager = Arc::new(BackendManager::new());
        manager
            .register(descriptor("npcap", &[BackendCapability::Capture]))
            .unwrap();
        manager
            .register(descriptor("windivert", &[BackendCapability::Capture]))
            .unwrap();
        running(&manager, "npcap");
        running(&manager, "windivert");

        let lb = LoadBalancer::new(manager);

        lb.report_started("npcap");
        lb.report_started("npcap");
        lb.report_started("npcap");

        let decision = lb.select(WorkKind::L3Capture);
        assert_eq!(decision.backend.as_deref(), Some("windivert"));
    }

    #[test]
    fn load_counters_are_observable() {
        let manager = Arc::new(BackendManager::new());
        let lb = LoadBalancer::new(manager);

        lb.report_started("npcap");
        lb.report_completed("npcap");
        lb.report_saturated("npcap");
        lb.report_failed("npcap");

        let load = lb.load_of("npcap");
        assert_eq!(load.completed, 1);
        assert_eq!(load.saturated, 1);
        assert_eq!(load.failed, 1);

        let stats = lb.stats();
        assert_eq!(stats.reported_completed, 1);
        assert_eq!(stats.reported_saturated, 1);
        assert_eq!(stats.reported_failed, 1);
    }

    #[test]
    fn loads_snapshot_is_deterministic() {
        let manager = Arc::new(BackendManager::new());
        let lb = LoadBalancer::new(manager);

        lb.report_started("z-backend");
        lb.report_started("a-backend");

        let loads = lb.loads();
        assert_eq!(loads.len(), 2);
        assert_eq!(loads[0].0, "a-backend");
        assert_eq!(loads[1].0, "z-backend");
    }
}