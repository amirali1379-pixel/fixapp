use network_core::ownership::{transition_ownership, OwnershipState, OwnershipTracker};
use network_core::statistics::{DropCategory, EngineStatistics};

#[test]
fn authoritative_ownership_chain_is_enforced() {
    let mut tracker = OwnershipTracker::new();
    tracker.transition(OwnershipState::BackendOwned).unwrap();
    tracker.handoff_backend_to_engine().unwrap();
    tracker.handoff_engine_to_bus().unwrap();
    tracker.handoff_bus_to_processing().unwrap();
    tracker.handoff_to_host().unwrap();
    tracker.release().unwrap();
    assert_eq!(tracker.current(), OwnershipState::Released);
}

#[test]
fn released_state_cannot_be_reused() {
    assert!(transition_ownership(OwnershipState::Released, OwnershipState::EngineOwned).is_err());
}

#[test]
fn drop_categories_remain_distinct() {
    let stats = EngineStatistics::new();
    stats.drops_host_requested.fetch_add(2, std::sync::atomic::Ordering::Relaxed);
    stats.drops_safety_error.fetch_add(3, std::sync::atomic::Ordering::Relaxed);
    stats.drops_backend_failure.fetch_add(4, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(stats.drops_host_requested.load(std::sync::atomic::Ordering::Relaxed), 2);
    assert_eq!(stats.drops_safety_error.load(std::sync::atomic::Ordering::Relaxed), 3);
    assert_eq!(stats.drops_backend_failure.load(std::sync::atomic::Ordering::Relaxed), 4);
    let _ = DropCategory::HostRequestedDrop;
    let _ = DropCategory::SafetyErrorDrop;
    let _ = DropCategory::BackendFailure;
}
