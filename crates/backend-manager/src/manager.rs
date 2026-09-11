// crates/backend-manager/src/manager.rs

#![forbid(unsafe_code)]

use crate::{
    BackendCapability,
    BackendDescriptor,
    BackendHealth,
    BackendLifecycle,
    BackendRole,
    BackendRuntimeState,
    CapabilityCoverage,
    CapabilitySet,
    CapabilityStatus,
    HealthMonitor,
};

use network_core::{
    EngineError,
    EngineErrorCode,
};

use packet_bus::PacketBus;
use std::collections::HashMap;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}, RwLock};

/// Backend selection/failover policy.
///
/// The policy controls backend *selection preference* only.
/// It does not define packet policy, filtering policy, DROP policy,
/// routing policy, NAT policy, or Gateway policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailoverPolicy {
    None,
    PreferPrimary,
    PreferHealthy,
    RoundRobin,
}

impl Default for FailoverPolicy {
    fn default() -> Self { Self::PreferHealthy }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityConflict {
    pub capability: BackendCapability,
    pub requesting_backend: String,
    pub active_backend: String,
    pub active_backend_role: BackendRole,
}

impl FailoverPolicy {
    pub fn should_failover(
        self,
        primary: Option<&BackendRuntimeState>,
        fallback: Option<&BackendRuntimeState>,
    ) -> bool {
        let fallback_available = fallback.map(|backend| backend.is_available()).unwrap_or(false);
        if !fallback_available { return false; }
        match self {
            Self::None => false,
            Self::PreferPrimary => primary.map(|backend| !backend.is_available()).unwrap_or(true),
            Self::PreferHealthy => primary.map(|backend| backend.lifecycle != BackendLifecycle::Running).unwrap_or(true),
            Self::RoundRobin => primary.map(|backend| !backend.is_available()).unwrap_or(true),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendManagerStats {
    pub registered: usize,
    pub running: usize,
    pub degraded: usize,
    pub failed: usize,
    pub stopped: usize,
}

impl BackendManagerStats { pub fn available(&self) -> usize { self.running + self.degraded } }

#[derive(Debug)]
struct ManagedBackend {
    runtime: BackendRuntimeState,
    health: HealthMonitor,
}

impl ManagedBackend {
    fn new(descriptor: BackendDescriptor) -> Self {
        Self { runtime: BackendRuntimeState::new(descriptor), health: HealthMonitor::default() }
    }
}

#[derive(Debug)]
pub struct BackendManager {
    backends: RwLock<HashMap<String, ManagedBackend>>,
    failover_policy: RwLock<FailoverPolicy>,
    pub(crate) round_robin_cursor: AtomicUsize,
}

impl BackendManager {
    pub fn new() -> Self {
        Self {
            backends: RwLock::new(HashMap::new()),
            failover_policy: RwLock::new(FailoverPolicy::default()),
            round_robin_cursor: AtomicUsize::new(0),
        }
    }

    pub fn register(&self, descriptor: BackendDescriptor) -> Result<(), EngineError> {
        if descriptor.name.trim().is_empty() { return Err(EngineError::Code(EngineErrorCode::InvalidArgument)); }
        let mut backends = self.backends.write().map_err(|_| EngineError::Code(EngineErrorCode::InternalError))?;
        if backends.contains_key(&descriptor.name) { return Err(EngineError::Code(EngineErrorCode::BackendAlreadyRegistered)); }
        let name = descriptor.name.clone();
        backends.insert(name, ManagedBackend::new(descriptor));
        Ok(())
    }

    pub fn unregister(&self, name: &str) -> Result<(), EngineError> {
        let mut backends = self.backends.write().map_err(|_| EngineError::Code(EngineErrorCode::InternalError))?;
        let backend = backends.get(name).ok_or_else(|| EngineError::Code(EngineErrorCode::BackendNotFound))?;
        if backend.runtime.lifecycle.is_active() { return Err(EngineError::Code(EngineErrorCode::ConcurrentOperation)); }
        backends.remove(name);
        Ok(())
    }

    pub fn contains(&self, name: &str) -> bool { self.backends.read().map(|b| b.contains_key(name)).unwrap_or(false) }
    pub fn count(&self) -> usize { self.backends.read().map(|b| b.len()).unwrap_or(0) }

    pub fn descriptor(&self, name: &str) -> Result<BackendDescriptor, EngineError> {
        let backends = self.backends.read().map_err(|_| EngineError::Code(EngineErrorCode::InternalError))?;
        backends.get(name).map(|b| b.runtime.descriptor.clone()).ok_or_else(|| EngineError::Code(EngineErrorCode::BackendNotFound))
    }

    pub fn runtime_state(&self, name: &str) -> Result<BackendRuntimeState, EngineError> {
        let backends = self.backends.read().map_err(|_| EngineError::Code(EngineErrorCode::InternalError))?;
        backends.get(name).map(|b| b.runtime.clone()).ok_or_else(|| EngineError::Code(EngineErrorCode::BackendNotFound))
    }

    pub fn health(&self, name: &str) -> Result<BackendHealth, EngineError> {
        let backends = self.backends.read().map_err(|_| EngineError::Code(EngineErrorCode::InternalError))?;
        backends.get(name).map(|b| b.health.health()).ok_or_else(|| EngineError::Code(EngineErrorCode::BackendNotFound))
    }

    pub fn capabilities(&self, name: &str) -> Result<CapabilitySet, EngineError> {
        let backends = self.backends.read().map_err(|_| EngineError::Code(EngineErrorCode::InternalError))?;
        backends.get(name).map(|b| b.runtime.descriptor.capabilities.clone()).ok_or_else(|| EngineError::Code(EngineErrorCode::BackendNotFound))
    }

    pub fn supports(&self, name: &str, capability: BackendCapability) -> Result<bool, EngineError> {
        let backends = self.backends.read().map_err(|_| EngineError::Code(EngineErrorCode::InternalError))?;
        backends.get(name).map(|b| b.runtime.supports(capability)).ok_or_else(|| EngineError::Code(EngineErrorCode::BackendNotFound))
    }

    pub fn set_lifecycle(&self, name: &str, lifecycle: BackendLifecycle) -> Result<(), EngineError> {
        let mut backends = self.backends.write().map_err(|_| EngineError::Code(EngineErrorCode::InternalError))?;
        let backend = backends.get_mut(name).ok_or_else(|| EngineError::Code(EngineErrorCode::BackendNotFound))?;
        backend.runtime.transition(lifecycle)?;
        match lifecycle {
            BackendLifecycle::Running => backend.health.force_health(BackendHealth::Healthy),
            BackendLifecycle::Failed => backend.health.force_health(BackendHealth::Unhealthy),
            _ => {}
        }
        Ok(())
    }

    pub fn check_activation_conflict(&self, name: &str) -> Result<Option<CapabilityConflict>, EngineError> {
        let backends = self.backends.read().map_err(|_| EngineError::Code(EngineErrorCode::InternalError))?;
        if !backends.contains_key(name) { return Err(EngineError::Code(EngineErrorCode::BackendNotFound)); }
        Ok(None)
    }

    pub fn start(&self, name: &str, _bus: Arc<PacketBus>) -> Result<(), EngineError> {
        let mut backends = self.backends.write().map_err(|_| EngineError::Code(EngineErrorCode::InternalError))?;
        let backend = backends.get_mut(name).ok_or_else(|| EngineError::Code(EngineErrorCode::BackendNotFound))?;
        if !backend.runtime.lifecycle.can_start() {
            return Err(if backend.runtime.lifecycle == BackendLifecycle::Running { EngineError::Code(EngineErrorCode::BackendAlreadyRunning) } else { EngineError::Code(EngineErrorCode::InvalidStateTransition) });
        }
        backend.runtime.transition(BackendLifecycle::Starting)
    }

    pub fn mark_running(&self, name: &str) -> Result<(), EngineError> { self.set_lifecycle(name, BackendLifecycle::Running) }

    pub fn stop(&self, name: &str) -> Result<(), EngineError> {
        let mut backends = self.backends.write().map_err(|_| EngineError::Code(EngineErrorCode::InternalError))?;
        let backend = backends.get_mut(name).ok_or_else(|| EngineError::Code(EngineErrorCode::BackendNotFound))?;
        if backend.runtime.lifecycle == BackendLifecycle::Stopped { return Err(EngineError::Code(EngineErrorCode::BackendNotRunning)); }
        if !backend.runtime.lifecycle.can_stop() { return Err(EngineError::Code(EngineErrorCode::InvalidStateTransition)); }
        backend.runtime.transition(BackendLifecycle::Stopping)
    }

    pub fn mark_stopped(&self, name: &str) -> Result<(), EngineError> { self.set_lifecycle(name, BackendLifecycle::Stopped) }

    pub fn record_success(&self, name: &str) -> Result<BackendHealth, EngineError> {
        let mut backends = self.backends.write().map_err(|_| EngineError::Code(EngineErrorCode::InternalError))?;
        let backend = backends.get_mut(name).ok_or_else(|| EngineError::Code(EngineErrorCode::BackendNotFound))?;
        let health = backend.health.record_success();
        if health == BackendHealth::Healthy && backend.runtime.lifecycle == BackendLifecycle::Degraded { let _ = backend.runtime.transition(BackendLifecycle::Running); }
        Ok(health)
    }

    pub fn record_failure(&self, name: &str, native_error: Option<i32>) -> Result<BackendHealth, EngineError> {
        let mut backends = self.backends.write().map_err(|_| EngineError::Code(EngineErrorCode::InternalError))?;
        let backend = backends.get_mut(name).ok_or_else(|| EngineError::Code(EngineErrorCode::BackendNotFound))?;
        backend.runtime.record_error(native_error);
        let health = backend.health.record_failure();
        match health {
            BackendHealth::Unhealthy => {
                if backend.runtime.lifecycle != BackendLifecycle::Failed { backend.runtime.transition(BackendLifecycle::Failed)?; }
            }
            BackendHealth::Degraded => {
                if backend.runtime.lifecycle == BackendLifecycle::Running { backend.runtime.transition(BackendLifecycle::Degraded)?; }
            }
            BackendHealth::Healthy | BackendHealth::Unknown => {}
        }
        Ok(health)
    }

    pub fn set_failover_policy(&self, policy: FailoverPolicy) -> Result<(), EngineError> {
        let mut current = self.failover_policy.write().map_err(|_| EngineError::Code(EngineErrorCode::InternalError))?;
        *current = policy;
        Ok(())
    }

    pub fn failover_policy(&self) -> Result<FailoverPolicy, EngineError> {
        self.failover_policy.read().map(|policy| *policy).map_err(|_| EngineError::Code(EngineErrorCode::InternalError))
    }

    pub fn find_capable(&self, capability: BackendCapability) -> Vec<String> {
        let Ok(backends) = self.backends.read() else { return Vec::new(); };
        let mut result: Vec<String> = backends.iter().filter_map(|(name, backend)| if backend.runtime.is_available() && backend.runtime.supports(capability) { Some(name.clone()) } else { None }).collect();
        result.sort();
        result
    }

    pub fn find_healthy_capable(&self, capability: BackendCapability) -> Vec<String> {
        let Ok(backends) = self.backends.read() else { return Vec::new(); };
        let mut result: Vec<String> = backends.iter().filter_map(|(name, backend)| if backend.runtime.is_available() && backend.runtime.supports(capability) && backend.health.health() == BackendHealth::Healthy { Some(name.clone()) } else { None }).collect();
        result.sort();
        result
    }

    /// Legacy single-capability API retained for ABI/API compatibility.
    /// It now routes through the canonical capability-requirement selector,
    /// so public and internal single-capability selection share one policy.
    pub fn select_backend(&self, capability: BackendCapability) -> Option<String> {
        crate::selection::select_backend_for_requirements(
            self,
            &[crate::CapabilityRequirement::required(capability)],
        )
    }

    /// Backend Complementarity entry point.
    ///
    /// Returns the runtime coverage report for `capability`, taking the
    /// intended primary/fallback layout into account.
    ///
    /// The report is a description of the current runtime situation. It
    /// does not start, stop, or reconfigure any backend, and it does not
    /// mutate lifecycle or health state. The Engine is responsible for
    /// acting on the reported status.
    pub fn select_with_fallback(
        &self,
        capability: BackendCapability,
    ) -> CapabilityCoverage {
        crate::complementarity::select_with_fallback(self, capability)
    }

    /// Convenience wrapper for the coverage status.
    pub fn capability_status(
        &self,
        capability: BackendCapability,
    ) -> CapabilityStatus {
        crate::complementarity::capability_status(self, capability)
    }

    pub fn stats(&self) -> BackendManagerStats {
        let Ok(backends) = self.backends.read() else { return BackendManagerStats { registered: 0, running: 0, degraded: 0, failed: 0, stopped: 0 }; };
        let mut stats = BackendManagerStats { registered: backends.len(), running: 0, degraded: 0, failed: 0, stopped: 0 };
        for backend in backends.values() {
            match backend.runtime.lifecycle {
                BackendLifecycle::Running => stats.running += 1,
                BackendLifecycle::Degraded => stats.degraded += 1,
                BackendLifecycle::Failed => stats.failed += 1,
                BackendLifecycle::Stopped | BackendLifecycle::Disabled => stats.stopped += 1,
                BackendLifecycle::Starting | BackendLifecycle::Stopping => {}
            }
        }
        stats
    }

    pub fn names(&self) -> Vec<String> {
        let Ok(backends) = self.backends.read() else { return Vec::new(); };
        let mut names: Vec<String> = backends.keys().cloned().collect();
        names.sort();
        names
    }

    pub fn descriptors(&self) -> Vec<BackendDescriptor> {
        let Ok(backends) = self.backends.read() else { return Vec::new(); };
        let mut descriptors: Vec<BackendDescriptor> = backends.values().map(|backend| backend.runtime.descriptor.clone()).collect();
        descriptors.sort_by(|a, b| a.name.cmp(&b.name));
        descriptors
    }
}

impl Default for BackendManager { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(name: &str, capabilities: &[BackendCapability]) -> BackendDescriptor {
        BackendDescriptor::new(name, "1.0.0", "test backend", CapabilitySet::from(capabilities.iter().copied()))
    }

    #[test]
    fn registers_backend() {
        let manager = BackendManager::new();
        manager.register(descriptor("test", &[BackendCapability::Capture])).unwrap();
        assert!(manager.contains("test"));
        assert_eq!(manager.count(), 1);
    }

    #[test]
    fn duplicate_registration_fails() {
        let manager = BackendManager::new();
        manager.register(descriptor("test", &[])).unwrap();
        let result = manager.register(descriptor("test", &[]));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), EngineErrorCode::BackendAlreadyRegistered);
    }

    #[test]
    fn capabilities_are_backend_specific() {
        let manager = BackendManager::new();
        manager.register(descriptor("capture", &[BackendCapability::Capture])).unwrap();
        manager.register(descriptor("filter", &[BackendCapability::Filtering])).unwrap();
        assert!(manager.supports("capture", BackendCapability::Capture).unwrap());
        assert!(!manager.supports("capture", BackendCapability::Filtering).unwrap());
        assert!(manager.supports("filter", BackendCapability::Filtering).unwrap());
    }

    #[test]
    fn lifecycle_is_managed() {
        let manager = BackendManager::new();
        let bus = Arc::new(PacketBus::new(100));
        manager.register(descriptor("test", &[])).unwrap();
        manager.start("test", bus.clone()).unwrap();
        assert_eq!(manager.runtime_state("test").unwrap().lifecycle, BackendLifecycle::Starting);
        manager.mark_running("test").unwrap();
        assert_eq!(manager.runtime_state("test").unwrap().lifecycle, BackendLifecycle::Running);
    }

    #[test]
    fn start_running_fails() {
        let manager = BackendManager::new();
        let bus = Arc::new(PacketBus::new(100));
        manager.register(descriptor("test", &[])).unwrap();
        manager.start("test", bus.clone()).unwrap();
        manager.mark_running("test").unwrap();
        let result = manager.start("test", bus.clone());
        assert_eq!(result.unwrap_err().code(), EngineErrorCode::BackendAlreadyRunning);
    }

    #[test]
    fn capable_backend_search_is_deterministic() {
        let manager = BackendManager::new();
        let bus = Arc::new(PacketBus::new(100));
        manager.register(descriptor("z-capture", &[BackendCapability::Capture])).unwrap();
        manager.register(descriptor("a-capture", &[BackendCapability::Capture])).unwrap();
        manager.start("z-capture", bus.clone()).unwrap(); manager.mark_running("z-capture").unwrap();
        manager.start("a-capture", bus.clone()).unwrap(); manager.mark_running("a-capture").unwrap();
        assert_eq!(manager.find_capable(BackendCapability::Capture), vec!["a-capture".to_string(), "z-capture".to_string()]);
    }

    #[test]
    fn unavailable_backend_is_not_selected() {
        let manager = BackendManager::new();
        manager.register(descriptor("capture", &[BackendCapability::Capture])).unwrap();
        assert!(manager.find_capable(BackendCapability::Capture).is_empty());
    }

    #[test]
    fn failure_marks_backend_failed() {
        let manager = BackendManager::new();
        let bus = Arc::new(PacketBus::new(100));
        manager.register(descriptor("test", &[])).unwrap();
        manager.start("test", bus.clone()).unwrap(); manager.mark_running("test").unwrap();
        manager.record_failure("test", Some(42)).unwrap(); manager.record_failure("test", Some(42)).unwrap(); manager.record_failure("test", Some(42)).unwrap();
        let runtime = manager.runtime_state("test").unwrap();
        assert_eq!(runtime.lifecycle, BackendLifecycle::Failed);
        assert_eq!(runtime.error_count, 3); assert_eq!(runtime.last_native_error, Some(42));
    }

    #[test]
    fn statistics_are_correct() {
        let manager = BackendManager::new(); let bus = Arc::new(PacketBus::new(100));
        manager.register(descriptor("a", &[])).unwrap(); manager.register(descriptor("b", &[])).unwrap(); manager.register(descriptor("c", &[])).unwrap();
        manager.start("a", bus.clone()).unwrap(); manager.mark_running("a").unwrap();
        manager.start("b", bus.clone()).unwrap(); manager.mark_running("b").unwrap(); manager.record_failure("b", None).unwrap(); manager.record_failure("b", None).unwrap();
        let stats = manager.stats(); assert_eq!(stats.registered, 3); assert_eq!(stats.running, 1); assert_eq!(stats.degraded, 1); assert_eq!(stats.stopped, 1);
    }

    #[test]
    fn unregister_stopped_backend() { let manager = BackendManager::new(); manager.register(descriptor("test", &[])).unwrap(); manager.unregister("test").unwrap(); assert!(!manager.contains("test")); }

    #[test]
    fn cannot_unregister_active_backend() {
        let manager = BackendManager::new(); let bus = Arc::new(PacketBus::new(100)); manager.register(descriptor("test", &[])).unwrap(); manager.start("test", bus.clone()).unwrap(); manager.mark_running("test").unwrap();
        assert_eq!(manager.unregister("test").unwrap_err().code(), EngineErrorCode::ConcurrentOperation);
    }

    #[test]
    fn failover_policy_can_change() { let manager = BackendManager::new(); manager.set_failover_policy(FailoverPolicy::None).unwrap(); assert_eq!(manager.failover_policy().unwrap(), FailoverPolicy::None); }

    #[test]
    fn descriptors_are_available_and_sorted() {
        let manager = BackendManager::new(); manager.register(descriptor("z-test", &[BackendCapability::Capture])).unwrap(); manager.register(descriptor("a-test", &[BackendCapability::Capture])).unwrap();
        let descriptors = manager.descriptors(); assert_eq!(descriptors.len(), 2); assert_eq!(descriptors[0].name, "a-test"); assert_eq!(descriptors[1].name, "z-test");
    }

    #[test]
    fn non_overlapping_backends_can_both_run() {
        let manager = BackendManager::new(); let bus = Arc::new(PacketBus::new(100));
        manager.register(descriptor("wfp", &[BackendCapability::Filtering])).unwrap(); manager.register(descriptor("npcap", &[BackendCapability::L2Capture])).unwrap();
        manager.start("wfp", bus.clone()).unwrap(); manager.mark_running("wfp").unwrap(); manager.start("npcap", bus.clone()).unwrap(); assert!(manager.mark_running("npcap").is_ok());
    }

    #[test]
    fn capability_overlap_does_not_imply_conflict() {
        let manager = BackendManager::new(); let bus = Arc::new(PacketBus::new(100));
        manager.register(descriptor("wfp", &[BackendCapability::Filtering]).primary()).unwrap(); manager.register(descriptor("windivert", &[BackendCapability::Filtering, BackendCapability::Reinjection])).unwrap();
        manager.start("wfp", bus.clone()).unwrap(); manager.mark_running("wfp").unwrap(); manager.start("windivert", bus.clone()).unwrap(); assert!(manager.mark_running("windivert").is_ok());
    }

    #[test]
    fn activation_conflict_requires_scope_aware_engine_logic() {
        let manager = BackendManager::new(); let bus = Arc::new(PacketBus::new(100));
        manager.register(descriptor("wfp", &[BackendCapability::Filtering]).primary()).unwrap(); manager.register(descriptor("windivert", &[BackendCapability::Filtering])).unwrap(); manager.start("wfp", bus.clone()).unwrap(); manager.mark_running("wfp").unwrap();
        assert!(manager.check_activation_conflict("windivert").unwrap().is_none());
    }

    #[test]
    fn stopping_backend_does_not_affect_other_backend() {
        let manager = BackendManager::new(); let bus = Arc::new(PacketBus::new(100));
        manager.register(descriptor("wfp", &[BackendCapability::Filtering])).unwrap(); manager.register(descriptor("windivert", &[BackendCapability::Filtering])).unwrap();
        manager.start("wfp", bus.clone()).unwrap(); manager.mark_running("wfp").unwrap(); manager.start("windivert", bus.clone()).unwrap(); manager.mark_running("windivert").unwrap(); manager.stop("wfp").unwrap(); manager.mark_stopped("wfp").unwrap();
        assert_eq!(manager.runtime_state("wfp").unwrap().lifecycle, BackendLifecycle::Stopped); assert_eq!(manager.runtime_state("windivert").unwrap().lifecycle, BackendLifecycle::Running);
    }

    #[test]
    fn prefer_healthy_selects_healthy_backend() {
        let manager = BackendManager::new(); let bus = Arc::new(PacketBus::new(100));
        manager.register(descriptor("degraded", &[BackendCapability::Capture])).unwrap(); manager.register(descriptor("healthy", &[BackendCapability::Capture])).unwrap(); manager.start("degraded", bus.clone()).unwrap(); manager.mark_running("degraded").unwrap(); manager.record_failure("degraded", None).unwrap(); manager.record_failure("degraded", None).unwrap(); manager.start("healthy", bus.clone()).unwrap(); manager.mark_running("healthy").unwrap(); manager.set_failover_policy(FailoverPolicy::PreferHealthy).unwrap();
        assert_eq!(manager.select_backend(BackendCapability::Capture), Some("healthy".to_string()));
    }

    #[test]
    fn round_robin_rotates_candidates() {
        let manager = BackendManager::new(); let bus = Arc::new(PacketBus::new(100));
        manager.register(descriptor("a", &[BackendCapability::Capture])).unwrap(); manager.register(descriptor("b", &[BackendCapability::Capture])).unwrap(); manager.start("a", bus.clone()).unwrap(); manager.mark_running("a").unwrap(); manager.start("b", bus.clone()).unwrap(); manager.mark_running("b").unwrap(); manager.set_failover_policy(FailoverPolicy::RoundRobin).unwrap();
        assert_eq!(manager.select_backend(BackendCapability::Capture), Some("a".to_string())); assert_eq!(manager.select_backend(BackendCapability::Capture), Some("b".to_string())); assert_eq!(manager.select_backend(BackendCapability::Capture), Some("a".to_string()));
    }

    #[test]
    fn missing_backend_conflict_check_fails() { let manager = BackendManager::new(); assert_eq!(manager.check_activation_conflict("missing").unwrap_err().code(), EngineErrorCode::BackendNotFound); }

    #[test]
    fn record_success_restores_degraded_backend_to_running() {
        let manager = BackendManager::new(); let bus = Arc::new(PacketBus::new(100)); manager.register(descriptor("degraded", &[BackendCapability::Capture])).unwrap(); manager.start("degraded", bus.clone()).unwrap(); manager.mark_running("degraded").unwrap(); manager.record_failure("degraded", None).unwrap(); manager.record_failure("degraded", None).unwrap(); assert_eq!(manager.runtime_state("degraded").unwrap().lifecycle, BackendLifecycle::Degraded); manager.record_success("degraded").unwrap(); assert_eq!(manager.runtime_state("degraded").unwrap().lifecycle, BackendLifecycle::Running);
    }

    #[test]
    fn select_with_fallback_returns_available_for_primary() {
        let manager = BackendManager::new(); let bus = Arc::new(PacketBus::new(100));
        manager.register(descriptor("npcap", &[BackendCapability::Capture])).unwrap();
        manager.start("npcap", bus).unwrap(); manager.mark_running("npcap").unwrap();
        let coverage = manager.select_with_fallback(BackendCapability::Capture);
        assert_eq!(coverage.status, CapabilityStatus::Available);
        assert_eq!(coverage.active.as_deref(), Some("npcap"));
    }

    #[test]
    fn capability_status_helper_matches_coverage() {
        let manager = BackendManager::new();
        assert_eq!(
            manager.capability_status(BackendCapability::Capture),
            CapabilityStatus::Unavailable,
        );
    }
}