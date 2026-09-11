#![forbid(unsafe_code)]

use crate::{
    check_requirements,
    BackendCapability,
    BackendHealth,
    BackendLifecycle,
    BackendManager,
    BackendRole,
    CapabilityRequirement,
    FailoverPolicy,
};

/// Finds backends that are operational and satisfy every required
/// capability in `requirements`.
///
/// Optional capabilities are deliberately non-blocking: a backend remains
/// eligible when it is missing an optional capability. This keeps capability
/// availability separate from runtime policy.
pub fn find_capable_requirements(
    manager: &BackendManager,
    requirements: &[CapabilityRequirement],
) -> Vec<String> {
    let mut candidates = Vec::new();

    for name in manager.names() {
        let Ok(runtime) = manager.runtime_state(&name) else {
            continue;
        };

        if !matches!(runtime.lifecycle, BackendLifecycle::Running | BackendLifecycle::Degraded) {
            continue;
        }

        let Ok(capabilities) = manager.capabilities(&name) else {
            continue;
        };

        let check = check_requirements(&capabilities, requirements);
        if check.is_satisfied() {
            candidates.push(name);
        }
    }

    candidates.sort_unstable();
    candidates
}

/// Finds operational backends satisfying all required capabilities and
/// currently reporting healthy status.
pub fn find_healthy_capable_requirements(
    manager: &BackendManager,
    requirements: &[CapabilityRequirement],
) -> Vec<String> {
    find_capable_requirements(manager, requirements)
        .into_iter()
        .filter(|name| manager.health(name).ok() == Some(BackendHealth::Healthy))
        .collect()
}

fn select_from_candidates(manager: &BackendManager, candidates: &[String]) -> Option<String> {
    if candidates.is_empty() {
        return None;
    }

    let policy = manager.failover_policy().ok()?;

    match policy {
        FailoverPolicy::None => candidates.first().cloned(),
        FailoverPolicy::PreferPrimary => candidates
            .iter()
            .find(|name| {
                manager
                    .runtime_state(name)
                    .map(|runtime| runtime.descriptor.role == BackendRole::Primary)
                    .unwrap_or(false)
            })
            .cloned()
            .or_else(|| candidates.first().cloned()),
        FailoverPolicy::PreferHealthy => candidates
            .iter()
            .find(|name| manager.health(name).ok() == Some(BackendHealth::Healthy))
            .cloned()
            .or_else(|| candidates.first().cloned()),
        FailoverPolicy::RoundRobin => {
            let index = manager
                .round_robin_cursor
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                % candidates.len();
            candidates.get(index).cloned()
        }
    }
}

/// Selects one backend for a multi-capability requirement set using the
/// manager's existing selection policy and round-robin cursor.
///
/// Selection never starts, stops, or otherwise mutates a native backend.
/// `PreferHealthy` prefers healthy candidates but may fall back to a
/// lifecycle-available degraded candidate, matching the existing selection
/// contract.
pub fn select_backend_for_requirements(
    manager: &BackendManager,
    requirements: &[CapabilityRequirement],
) -> Option<String> {
    select_from_candidates(manager, &find_capable_requirements(manager, requirements))
}

/// Selects a healthy failover candidate using the manager's failover policy.
/// The failed backend is excluded before policy selection, and every remaining
/// candidate must be lifecycle-available, healthy, and capable of the
/// requested operation.
///
/// `FailoverPolicy::None` explicitly disables intentional failover and
/// therefore produces no candidate. Other policies only control preference;
/// they never mutate backend lifecycle or health.
pub fn select_healthy_backend_for_failover(
    manager: &BackendManager,
    capability: BackendCapability,
    excluded_backend: &str,
) -> Option<String> {
    if manager.failover_policy().ok()? == FailoverPolicy::None {
        return None;
    }

    let requirements = [CapabilityRequirement::required(capability)];
    let candidates = find_healthy_capable_requirements(manager, &requirements)
        .into_iter()
        .filter(|name| name != excluded_backend)
        .collect::<Vec<_>>();

    select_from_candidates(manager, &candidates)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BackendDescriptor, CapabilitySet};
    use packet_bus::PacketBus;
    use std::sync::Arc;

    fn descriptor(name: &str, capabilities: &[BackendCapability]) -> BackendDescriptor {
        BackendDescriptor::new(
            name,
            "1.0.0",
            "selection test backend",
            CapabilitySet::from(capabilities.iter().copied()),
        )
    }

    fn running(manager: &BackendManager, name: &str) {
        let bus = Arc::new(PacketBus::new(100));
        manager.start(name, bus).unwrap();
        manager.mark_running(name).unwrap();
    }

    #[test]
    fn requires_all_required_capabilities() {
        let manager = BackendManager::new();
        manager.register(descriptor("capture-only", &[BackendCapability::Capture])).unwrap();
        manager.register(descriptor("capture-filter", &[BackendCapability::Capture, BackendCapability::Filtering])).unwrap();
        running(&manager, "capture-only");
        running(&manager, "capture-filter");

        let requirements = [
            CapabilityRequirement::required(BackendCapability::Capture),
            CapabilityRequirement::required(BackendCapability::Filtering),
        ];

        assert_eq!(find_capable_requirements(&manager, &requirements), vec!["capture-filter".to_string()]);
    }

    #[test]
    fn optional_capability_does_not_reject_candidate() {
        let manager = BackendManager::new();
        manager.register(descriptor("capture", &[BackendCapability::Capture])).unwrap();
        running(&manager, "capture");

        let requirements = [
            CapabilityRequirement::required(BackendCapability::Capture),
            CapabilityRequirement::optional(BackendCapability::Filtering),
        ];

        assert_eq!(find_capable_requirements(&manager, &requirements), vec!["capture".to_string()]);
    }

    #[test]
    fn unavailable_and_failed_backends_are_rejected() {
        let manager = BackendManager::new();
        manager.register(descriptor("stopped", &[BackendCapability::Capture])).unwrap();
        manager.register(descriptor("running", &[BackendCapability::Capture])).unwrap();
        running(&manager, "running");

        let requirements = [CapabilityRequirement::required(BackendCapability::Capture)];
        assert_eq!(find_capable_requirements(&manager, &requirements), vec!["running".to_string()]);
    }

    #[test]
    fn primary_is_preferred() {
        let manager = BackendManager::new();
        manager.register(descriptor("supplementary", &[BackendCapability::Capture]).role(BackendRole::Supplementary)).unwrap();
        manager.register(descriptor("primary", &[BackendCapability::Capture]).role(BackendRole::Primary)).unwrap();
        running(&manager, "supplementary");
        running(&manager, "primary");
        manager.set_failover_policy(FailoverPolicy::PreferPrimary).unwrap();

        let requirements = [CapabilityRequirement::required(BackendCapability::Capture)];
        assert_eq!(select_backend_for_requirements(&manager, &requirements), Some("primary".to_string()));
    }

    #[test]
    fn failover_excludes_failed_backend_and_requires_healthy_candidate() {
        let manager = BackendManager::new();
        manager.register(descriptor("failed", &[BackendCapability::Capture])).unwrap();
        manager.register(descriptor("healthy", &[BackendCapability::Capture])).unwrap();
        running(&manager, "failed");
        running(&manager, "healthy");
        manager.set_lifecycle("failed", BackendLifecycle::Failed).unwrap();
        manager.record_success("healthy").unwrap();

        assert_eq!(select_healthy_backend_for_failover(&manager, BackendCapability::Capture, "failed"), Some("healthy".to_string()));
    }

    #[test]
    fn failover_does_not_select_degraded_candidate() {
        let manager = BackendManager::new();
        manager.register(descriptor("degraded", &[BackendCapability::Capture])).unwrap();
        running(&manager, "degraded");
        manager.set_lifecycle("degraded", BackendLifecycle::Degraded).unwrap();

        assert_eq!(select_healthy_backend_for_failover(&manager, BackendCapability::Capture, "other"), None);
    }

    #[test]
    fn disabled_failover_policy_returns_no_failover_candidate() {
        let manager = BackendManager::new();
        manager.register(descriptor("healthy", &[BackendCapability::Capture])).unwrap();
        running(&manager, "healthy");
        manager.set_failover_policy(FailoverPolicy::None).unwrap();

        assert_eq!(select_healthy_backend_for_failover(&manager, BackendCapability::Capture, "failed"), None);
    }
}
