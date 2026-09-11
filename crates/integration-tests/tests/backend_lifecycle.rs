use backend_manager::{BackendCapability, BackendDescriptor, BackendLifecycle, BackendManager, CapabilitySet};
use packet_bus::PacketBus;
use std::sync::Arc;

fn manager() -> BackendManager {
    let manager = BackendManager::new();
    manager.register(BackendDescriptor::new(
        "capture-only", "1.0", "test backend",
        CapabilitySet::from([BackendCapability::Capture]),
    )).unwrap();
    manager
}

#[test]
fn registered_backend_reports_only_declared_capabilities() {
    let manager = manager();
    assert!(manager.supports("capture-only", BackendCapability::Capture).unwrap());
    assert!(!manager.supports("capture-only", BackendCapability::Reinjection).unwrap());
}

#[test]
fn lifecycle_starts_from_registered_state() {
    let manager = manager();
    let state = manager.runtime_state("capture-only").unwrap();
    assert_eq!(state.lifecycle, BackendLifecycle::Disabled);
}

#[test]
fn unknown_backend_is_not_reported_as_capable() {
    let manager = manager();
    assert!(manager.supports("missing", BackendCapability::Capture).is_err());
}

#[test]
fn backend_can_restart_after_clean_stop() {
    let manager = manager();
    let bus = Arc::new(PacketBus::new(8));

    manager.start("capture-only", Arc::clone(&bus)).unwrap();
    assert_eq!(manager.runtime_state("capture-only").unwrap().lifecycle, BackendLifecycle::Starting);

    manager.mark_running("capture-only").unwrap();
    assert_eq!(manager.runtime_state("capture-only").unwrap().lifecycle, BackendLifecycle::Running);

    manager.stop("capture-only").unwrap();
    assert_eq!(manager.runtime_state("capture-only").unwrap().lifecycle, BackendLifecycle::Stopping);

    manager.mark_stopped("capture-only").unwrap();
    assert_eq!(manager.runtime_state("capture-only").unwrap().lifecycle, BackendLifecycle::Stopped);

    manager.start("capture-only", bus).unwrap();
    assert_eq!(manager.runtime_state("capture-only").unwrap().lifecycle, BackendLifecycle::Starting);
}
