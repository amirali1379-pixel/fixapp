// dll/network-engine/src/coordination.rs

//! Multi-backend coordination for packet processing.
//!
//! When an observation needs capabilities the source backend does not
//! provide, the Engine can route it through other backends that do.
//!
//! Example:
//!
//! ```text
//! Npcap captures L2 packet
//!     ↓
//! Npcap cannot filter
//!     ↓
//! Engine identifies WinDivert as the filtering provider
//!     ↓
//! Result includes WinDivert as a participant
//! ```
//!
//! ## Scope
//!
//! This module is a **planning layer**. It reports which backends
//! participate in satisfying a required capability set, and whether
//! coverage is complete.
//!
//! It also exposes a **load-balanced work selector** that uses the
//! Engine's Load Balancer to pick the best backend for a given kind
//! of work (L2 observation, L3 capture, filtering, metadata, ...).
//!
//! It does NOT:
//! - start, stop, or reconfigure native backends
//! - execute native operations
//! - transfer native contexts between backends
//! - fabricate capability availability
//! - modify raw packet data
//! - drop packets
//!
//! Native execution remains the responsibility of the backends that
//! declare the capability.

#![forbid(unsafe_code)]

use std::sync::Arc;

use backend_manager::{
    BackendCapability,
    BackendManager,
    CapabilityStatus,
};
use network_core::observation::PacketObservation;

use crate::load_balancer::{
    LoadBalancer,
    LoadDecision,
    WorkKind,
};

/// Summary of coverage for one capability.
///
/// `status` is the runtime status from `BackendManager::select_with_fallback`.
#[derive(Debug, Clone)]
pub struct CapabilityCoverageSummary {
    pub capability: BackendCapability,
    pub status: CapabilityStatus,
    pub active: Option<String>,
    pub primary: Vec<String>,
    pub fallbacks: Vec<String>,
}

/// Result of coordinating an observation through the backend catalog.
///
/// `observation` is preserved unchanged. This is a planning result, not
/// an execution result.
#[derive(Debug, Clone)]
pub struct CoordinatedObservation {
    /// The observation that was planned for processing.
    pub observation: PacketObservation,

    /// Backend names that participate in satisfying the required
    /// capability set.
    pub participated: Vec<String>,

    /// Capabilities that could be satisfied by the source backend or a
    /// fallback backend.
    pub applied_capabilities: Vec<BackendCapability>,

    /// True when every required capability is satisfied.
    pub complete: bool,

    /// Capabilities that could not be satisfied by any backend.
    pub missing: Vec<BackendCapability>,
}

impl CoordinatedObservation {
    /// Returns true when at least one fallback backend participates
    /// beyond the source backend.
    pub fn uses_fallback(&self) -> bool {
        self.participated.len() > 1
    }
}

/// Multi-backend coordination planner.
///
/// Holds a reference to the `BackendManager` so it can query runtime
/// capability coverage, plus an optional reference to the Engine's
/// `LoadBalancer` for load-aware selection.
#[derive(Debug)]
pub struct MultiBackendCoordinator {
    manager: Arc<BackendManager>,
    load_balancer: Option<Arc<LoadBalancer>>,
}

impl MultiBackendCoordinator {
    /// Creates a coordinator without a Load Balancer.
    ///
    /// Selection uses the `BackendManager` coverage report only. This
    /// constructor is retained for tests and for callers that do not
    /// need load-aware routing.
    pub fn new(manager: Arc<BackendManager>) -> Self {
        Self {
            manager,
            load_balancer: None,
        }
    }

    /// Creates a coordinator with a Load Balancer.
    ///
    /// Load-aware selection is available through
    /// `select_backend_for_work` and `plan_load_balanced_processing`.
    pub fn with_load_balancer(
        manager: Arc<BackendManager>,
        load_balancer: Arc<LoadBalancer>,
    ) -> Self {
        Self {
            manager,
            load_balancer: Some(load_balancer),
        }
    }

    /// Returns the Load Balancer, if one was attached.
    pub fn load_balancer(&self) -> Option<Arc<LoadBalancer>> {
        self.load_balancer.as_ref().map(Arc::clone)
    }

    /// Plans processing of an observation against a required capability set.
    ///
    /// For each required capability, the planner:
    ///   1. Checks whether the source backend declares it.
    ///   2. If not, asks the `BackendManager` for a fallback provider.
    ///   3. Records the participant and capability, or records a miss.
    ///
    /// Native execution is not performed.
    pub fn coordinate(
        &self,
        observation: PacketObservation,
        required: &[BackendCapability],
    ) -> CoordinatedObservation {
        let source_backend = backend_name_for_source(&observation);

        let mut participated: Vec<String> = Vec::new();
        let mut applied: Vec<BackendCapability> = Vec::new();
        let mut missing: Vec<BackendCapability> = Vec::new();

        for capability in required {
            // 1. Prefer the source backend if it declares the capability.
            if let Some(source) = source_backend.as_deref() {
                if self
                    .manager
                    .supports(source, *capability)
                    .unwrap_or(false)
                {
                    if !participated.iter().any(|n| n == source) {
                        participated.push(source.to_string());
                    }
                    applied.push(*capability);
                    continue;
                }
            }

            // 2. Fall back to the manager's coverage report.
            let coverage = self.manager.select_with_fallback(*capability);

            match coverage.active {
                Some(active) => {
                    if !participated.iter().any(|n| n == &active) {
                        participated.push(active);
                    }
                    applied.push(*capability);
                }
                None => {
                    missing.push(*capability);
                }
            }
        }

        participated.sort();
        applied.sort_by_key(|c| c.sort_key());
        missing.sort_by_key(|c| c.sort_key());

        CoordinatedObservation {
            observation,
            participated,
            applied_capabilities: applied,
            complete: missing.is_empty(),
            missing,
        }
    }

    /// Returns a load-aware decision for the given kind of work.
    ///
    /// When no Load Balancer is attached, this method reports the work
    /// as unrouted. It does not fabricate a backend.
    pub fn select_backend_for_work(&self, kind: WorkKind) -> LoadDecision {
        match self.load_balancer.as_ref() {
            Some(lb) => lb.select(kind),
            None => LoadDecision {
                backend: None,
                capability: kind.primary_capability(),
                used_fallback: false,
            },
        }
    }

    /// Plans load-balanced processing for an observation.
    ///
    /// This combines capability coverage (via `coordinate`) with
    /// load-aware selection (via the Load Balancer) so the Engine can
    /// decide both **what** work is required and **where** it should be
    /// executed.
    ///
    /// Native execution is not performed here.
    pub fn plan_load_balanced_processing(
        &self,
        observation: PacketObservation,
        required: &[BackendCapability],
        work_kind: WorkKind,
    ) -> LoadBalancedPlan {
        let coverage = self.coordinate(observation, required);
        let decision = self.select_backend_for_work(work_kind);

        LoadBalancedPlan { coverage, decision }
    }

    /// Reports the current capability coverage for every known capability.
    ///
    /// This is a diagnostic snapshot. It does not start, stop, or
    /// reconfigure any backend.
    pub fn coverage_report(&self) -> Vec<CapabilityCoverageSummary> {
        BackendCapability::all_known()
            .iter()
            .map(|capability| {
                let coverage = self.manager.select_with_fallback(*capability);
                CapabilityCoverageSummary {
                    capability: *capability,
                    status: coverage.status,
                    active: coverage.active,
                    primary: coverage.primary,
                    fallbacks: coverage.fallbacks,
                }
            })
            .collect()
    }
}

/// Combined planning result.
///
/// `coverage` reports which backends satisfy the required capability
/// set. `decision` reports which backend the Load Balancer selected for
/// the given kind of work.
#[derive(Debug, Clone)]
pub struct LoadBalancedPlan {
    pub coverage: CoordinatedObservation,
    pub decision: LoadDecision,
}

impl LoadBalancedPlan {
    /// Returns true when both coverage and routing succeeded.
    pub fn is_ready(&self) -> bool {
        self.coverage.complete && self.decision.is_routed()
    }
}

/// Returns the well-known backend name for the observation's source.
///
/// Returns `None` when the source has no well-known backend name.
fn backend_name_for_source(observation: &PacketObservation) -> Option<String> {
    use network_core::BackendSource;

    match observation.backend_source {
        BackendSource::Npcap => Some("npcap".to_string()),
        BackendSource::WinDivert => Some("windivert".to_string()),
        BackendSource::Wfp => Some("wfp".to_string()),
        BackendSource::IpHelper => Some("iphelper".to_string()),
        BackendSource::Etw => Some("etw".to_string()),
        BackendSource::Unknown => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use backend_manager::{
        BackendDescriptor,
        CapabilitySet,
    };
    use network_core::observation::{ObservationId, PacketObservation};
    use network_core::packet::Packet;
    use network_core::timestamp::Timestamp;
    use network_core::{BackendSource, Direction};
    use packet_bus::PacketBus;

    fn descriptor(
        name: &str,
        capabilities: &[BackendCapability],
    ) -> BackendDescriptor {
        BackendDescriptor::new(
            name,
            "0.1.0",
            "coordination test backend",
            CapabilitySet::from(capabilities.iter().copied()),
        )
    }

    fn running(manager: &BackendManager, name: &str) {
        let bus = Arc::new(PacketBus::new(64));
        manager.start(name, bus).unwrap();
        manager.mark_running(name).unwrap();
    }

    fn observation(source: BackendSource) -> PacketObservation {
        let now = Timestamp::now();
        PacketObservation::new(
            ObservationId::new(1),
            source,
            now,
            now,
            Direction::Inbound,
            "test",
            Packet::new(vec![1, 2, 3, 4]),
        )
    }

    #[test]
    fn source_backend_participates_when_capable() {
        let manager = Arc::new(BackendManager::new());
        manager
            .register(descriptor("npcap", &[BackendCapability::Capture]))
            .unwrap();
        running(&manager, "npcap");

        let coordinator = MultiBackendCoordinator::new(manager);
        let result = coordinator.coordinate(
            observation(BackendSource::Npcap),
            &[BackendCapability::Capture],
        );

        assert!(result.complete);
        assert_eq!(result.participated, vec!["npcap"]);
        assert_eq!(result.applied_capabilities, vec![BackendCapability::Capture]);
    }

    #[test]
    fn fallback_backend_participates_when_source_lacks_capability() {
        let manager = Arc::new(BackendManager::new());
        manager
            .register(descriptor("npcap", &[BackendCapability::Capture]))
            .unwrap();
        manager
            .register(descriptor("windivert", &[BackendCapability::Filtering]))
            .unwrap();
        running(&manager, "npcap");
        running(&manager, "windivert");

        let coordinator = MultiBackendCoordinator::new(manager);
        let result = coordinator.coordinate(
            observation(BackendSource::Npcap),
            &[BackendCapability::Capture, BackendCapability::Filtering],
        );

        assert!(result.complete);
        assert_eq!(
            result.participated,
            vec!["npcap".to_string(), "windivert".to_string()]
        );
        assert!(result.uses_fallback());
    }

    #[test]
    fn missing_capability_is_reported() {
        let manager = Arc::new(BackendManager::new());
        manager
            .register(descriptor("npcap", &[BackendCapability::Capture]))
            .unwrap();
        running(&manager, "npcap");

        let coordinator = MultiBackendCoordinator::new(manager);
        let result = coordinator.coordinate(
            observation(BackendSource::Npcap),
            &[BackendCapability::Capture, BackendCapability::Reinjection],
        );

        assert!(!result.complete);
        assert_eq!(result.missing, vec![BackendCapability::Reinjection]);
    }

    #[test]
    fn coverage_report_covers_all_known_capabilities() {
        let manager = Arc::new(BackendManager::new());
        let coordinator = MultiBackendCoordinator::new(manager);
        let report = coordinator.coverage_report();
        assert_eq!(report.len(), BackendCapability::all_known().len());
    }

    #[test]
    fn unknown_source_falls_back_to_manager_lookup() {
        let manager = Arc::new(BackendManager::new());
        manager
            .register(descriptor("npcap", &[BackendCapability::Capture]))
            .unwrap();
        running(&manager, "npcap");

        let coordinator = MultiBackendCoordinator::new(manager);
        let result = coordinator.coordinate(
            observation(BackendSource::Unknown),
            &[BackendCapability::Capture],
        );

        assert!(result.complete);
        assert_eq!(result.participated, vec!["npcap"]);
    }

    #[test]
    fn no_load_balancer_reports_unrouted() {
        let manager = Arc::new(BackendManager::new());
        manager
            .register(descriptor("npcap", &[BackendCapability::Capture]))
            .unwrap();
        running(&manager, "npcap");

        let coordinator = MultiBackendCoordinator::new(manager);
        let decision = coordinator.select_backend_for_work(WorkKind::L3Capture);

        assert!(!decision.is_routed());
        assert!(decision.backend.is_none());
    }

    #[test]
    fn load_balanced_plan_uses_load_balancer_when_attached() {
        use crate::load_balancer::LoadBalancer;

        let manager = Arc::new(BackendManager::new());
        manager
            .register(descriptor("npcap", &[BackendCapability::Capture]))
            .unwrap();
        running(&manager, "npcap");

        let lb = Arc::new(LoadBalancer::new(Arc::clone(&manager)));
        let coordinator =
            MultiBackendCoordinator::with_load_balancer(Arc::clone(&manager), lb);

        let plan = coordinator.plan_load_balanced_processing(
            observation(BackendSource::Npcap),
            &[BackendCapability::Capture],
            WorkKind::L3Capture,
        );

        assert!(plan.coverage.complete);
        assert!(plan.decision.is_routed());
        assert_eq!(plan.decision.backend.as_deref(), Some("npcap"));
        assert!(plan.is_ready());
    }
}