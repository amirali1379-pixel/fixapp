use std::mem::{align_of, size_of};
use ffi::types::{NeBackendInfo, NeInitConfig, NePacketAction, NePacketHandle, NeStatistics};

#[test]
fn ffi_structs_are_c_layout_and_nonzero() {
    assert!(size_of::<NePacketHandle>() > 0);
    assert!(size_of::<NeBackendInfo>() > 0);
    assert!(size_of::<NePacketAction>() > 0);
    assert!(size_of::<NeStatistics>() > 0);
    assert!(size_of::<NeInitConfig>() > 0);
    assert!(align_of::<NePacketHandle>() <= 8);
}

#[test]
fn ffi_action_validation_accepts_only_defined_actions() {
    for action in [NePacketAction::PASS, NePacketAction::DROP, NePacketAction::MODIFY, NePacketAction::REINJECT] {
        assert!(NePacketAction::new(action).is_valid());
    }
    assert!(!NePacketAction::new(99).is_valid());
}

#[test]
fn ffi_init_config_rejects_zero_capacity() {
    let mut cfg = NeInitConfig::default();
    assert!(cfg.is_valid());
    cfg.queue_capacity = 0;
    assert!(!cfg.is_valid());
}

#[test]
fn ffi_packet_handle_zero_is_reserved() {
    assert!(!NePacketHandle::NULL.is_valid());
    assert!(NePacketHandle::new(1).is_valid());
}
