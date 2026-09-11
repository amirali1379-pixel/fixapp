use backend_manager::{BackendCapability, BackendDescriptor, BackendLifecycle, BackendRuntimeState, CapabilitySet, FailoverPolicy};

fn backend(name: &str, capability: BackendCapability) -> BackendRuntimeState {
    BackendRuntimeState::new(BackendDescriptor::new(name, "1.0", "test", CapabilitySet::from([capability])))
}

fn mark_failed(state: &mut BackendRuntimeState) {
    state.transition(BackendLifecycle::Starting).unwrap();
    state.transition(BackendLifecycle::Failed).unwrap();
}

#[test]
fn failover_policy_never_fails_over_without_available_fallback() {
    let primary = backend("primary", BackendCapability::Capture);
    let fallback = backend("fallback", BackendCapability::Capture);
    assert!(!FailoverPolicy::PreferHealthy.should_failover(Some(&primary), Some(&fallback)));
}

#[test]
fn healthy_fallback_is_allowed_when_primary_is_not_running() {
    let mut primary = backend("primary", BackendCapability::Capture);
    let mut fallback = backend("fallback", BackendCapability::Capture);
    mark_failed(&mut primary);
    fallback.transition(BackendLifecycle::Starting).unwrap();
    fallback.transition(BackendLifecycle::Running).unwrap();
    assert!(FailoverPolicy::PreferHealthy.should_failover(Some(&primary), Some(&fallback)));
}

#[test]
fn incompatible_capability_is_not_used_as_capture_fallback() {
    let mut primary = backend("primary", BackendCapability::Capture);
    let mut fallback = backend("fallback", BackendCapability::Reinjection);
    mark_failed(&mut primary);
    fallback.transition(BackendLifecycle::Starting).unwrap();
    fallback.transition(BackendLifecycle::Running).unwrap();
    assert!(fallback.descriptor.supports(BackendCapability::Reinjection));
    assert!(!fallback.descriptor.supports(BackendCapability::Capture));
}
