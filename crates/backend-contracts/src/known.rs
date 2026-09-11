// crates/backend-contracts/src/known.rs

#![forbid(unsafe_code)]

use backend_manager::{
    BackendCapability,
    BackendDescriptor,
    BackendRole,
    CapabilitySet,
};

use crate::BackendKind;

/// Returns the descriptor for a well-known backend kind.
///
/// The descriptor reflects the Engine's **intended** capability layout.
/// It is not proof that a capability is available at runtime.
pub fn descriptor_for(kind: BackendKind) -> BackendDescriptor {
    match kind {
        BackendKind::Npcap => npcap_descriptor(),
        BackendKind::WinDivert => windivert_descriptor(),
        BackendKind::Wfp => wfp_descriptor(),
        BackendKind::IpHelper => iphelper_descriptor(),
        BackendKind::Etw => etw_descriptor(),
    }
}

/// Returns descriptors for all known backends in deterministic order.
pub fn all_known_descriptors() -> Vec<BackendDescriptor> {
    BackendKind::all()
        .iter()
        .map(|kind| descriptor_for(*kind))
        .collect()
}

pub fn npcap_descriptor() -> BackendDescriptor {
    BackendDescriptor::new(
        "npcap",
        "0.1.0",
        "Npcap Layer-2/raw packet acquisition backend",
        CapabilitySet::from([
            BackendCapability::Capture,
            BackendCapability::Inspection,
            BackendCapability::L2Capture,
            BackendCapability::RawEthernet,
            BackendCapability::AdapterEnumeration,
            BackendCapability::AddressMetadata,
            BackendCapability::ErrorReporting,
        ]),
    )
    .role(BackendRole::Primary)
}

pub fn windivert_descriptor() -> BackendDescriptor {
    BackendDescriptor::new(
        backend_windivert::WINDIVERT_BACKEND_NAME,
        backend_windivert::WINDIVERT_BACKEND_VERSION,
        "WinDivert IP-layer interception and packet-action backend",
        CapabilitySet::from([
            BackendCapability::Capture,
            BackendCapability::Interception,
            BackendCapability::Filtering,
            BackendCapability::Inspection,
            BackendCapability::Direction,
            BackendCapability::Ipv4,
            BackendCapability::Ipv6,
            BackendCapability::Tcp,
            BackendCapability::Udp,
            BackendCapability::Icmp,
            BackendCapability::IcmpV6,
            BackendCapability::NetworkLayer,
            BackendCapability::AddressMetadata,
            BackendCapability::Modification,
            BackendCapability::Drop,
            BackendCapability::Pass,
            BackendCapability::Reinjection,
            BackendCapability::QueueControl,
            BackendCapability::HandleLifetime,
            BackendCapability::ErrorReporting,
        ]),
    )
    .role(BackendRole::Primary)
}

pub fn wfp_descriptor() -> BackendDescriptor {
    BackendDescriptor::new(
        backend_wfp::WFP_BACKEND_NAME,
        backend_wfp::WFP_BACKEND_VERSION,
        "Windows Filtering Platform backend",
        CapabilitySet::from([
            BackendCapability::Filtering,
            BackendCapability::Inspection,
            BackendCapability::Interception,
            BackendCapability::WfpEngineAccess,
            BackendCapability::WfpFilters,
            BackendCapability::WfpLayers,
            BackendCapability::WfpFlows,
            BackendCapability::AddressMetadata,
            BackendCapability::ErrorReporting,
        ]),
    )
    .role(BackendRole::Primary)
}

pub fn iphelper_descriptor() -> BackendDescriptor {
    BackendDescriptor::new(
        "iphelper",
        "0.1.0",
        "Windows IP Helper network-state backend",
        CapabilitySet::from([
            BackendCapability::InterfaceInfo,
            BackendCapability::RouteInfo,
            BackendCapability::NeighborInfo,
            BackendCapability::GatewayInfo,
            BackendCapability::AdapterEnumeration,
            BackendCapability::ErrorReporting,
        ]),
    )
}

pub fn etw_descriptor() -> BackendDescriptor {
    BackendDescriptor::new(
        "etw",
        "0.1.0",
        "Windows ETW diagnostics and telemetry backend",
        CapabilitySet::from([
            BackendCapability::Diagnostics,
            BackendCapability::Telemetry,
            BackendCapability::ErrorReporting,
        ]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_kinds_have_descriptors() {
        for kind in BackendKind::all() {
            let descriptor = descriptor_for(*kind);
            assert_eq!(descriptor.name, kind.name());
        }
    }

    #[test]
    fn all_known_descriptors_is_deterministic() {
        let a = all_known_descriptors();
        let b = all_known_descriptors();
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.name, y.name);
            assert_eq!(x.version, y.version);
        }
    }

    #[test]
    fn windivert_uses_backend_constants() {
        let descriptor = windivert_descriptor();
        assert_eq!(descriptor.name, backend_windivert::WINDIVERT_BACKEND_NAME);
        assert_eq!(descriptor.version, backend_windivert::WINDIVERT_BACKEND_VERSION);
    }

    #[test]
    fn wfp_uses_backend_constants() {
        let descriptor = wfp_descriptor();
        assert_eq!(descriptor.name, backend_wfp::WFP_BACKEND_NAME);
        assert_eq!(descriptor.version, backend_wfp::WFP_BACKEND_VERSION);
    }

    #[test]
    fn npcap_declares_l2_capture() {
        let descriptor = npcap_descriptor();
        assert!(descriptor.supports(BackendCapability::L2Capture));
        assert!(descriptor.supports(BackendCapability::Capture));
        assert!(!descriptor.supports(BackendCapability::Modification));
    }

    #[test]
    fn windivert_declares_ip_and_actions() {
        let descriptor = windivert_descriptor();
        assert!(descriptor.supports(BackendCapability::Ipv4));
        assert!(descriptor.supports(BackendCapability::Tcp));
        assert!(descriptor.supports(BackendCapability::Modification));
        assert!(descriptor.supports(BackendCapability::Pass));
        assert!(descriptor.supports(BackendCapability::Drop));
        assert!(descriptor.supports(BackendCapability::Reinjection));
    }

    #[test]
    fn wfp_declares_filtering() {
        let descriptor = wfp_descriptor();
        assert!(descriptor.supports(BackendCapability::Filtering));
        assert!(descriptor.supports(BackendCapability::WfpFilters));
    }

    #[test]
    fn iphelper_declares_network_state() {
        let descriptor = iphelper_descriptor();
        assert!(descriptor.supports(BackendCapability::RouteInfo));
        assert!(descriptor.supports(BackendCapability::NeighborInfo));
        assert!(descriptor.supports(BackendCapability::InterfaceInfo));
    }

    #[test]
    fn etw_declares_diagnostics() {
        let descriptor = etw_descriptor();
        assert!(descriptor.supports(BackendCapability::Diagnostics));
        assert!(descriptor.supports(BackendCapability::Telemetry));
    }
}