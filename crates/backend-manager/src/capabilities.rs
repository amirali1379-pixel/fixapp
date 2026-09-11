#![forbid(unsafe_code)]

use std::collections::HashSet;

/// Native/backend capabilities exposed to the Engine.
///
/// This enum describes what a backend can technically provide.
/// It does NOT describe Host policy.
///
/// In particular:
/// - capability != policy
/// - capability != lifecycle
/// - capability != health
/// - capability != traffic scope
/// - capability != authorization
///
/// The Engine must still validate actual runtime availability before
/// executing an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum BackendCapability {
    // -----------------------------------------------------------------
    // Generic packet capabilities
    // -----------------------------------------------------------------

    Capture = 0,
    Interception = 1,
    Filtering = 2,
    Inspection = 3,
    Direction = 4,

    // -----------------------------------------------------------------
    // Network / protocol capabilities
    // -----------------------------------------------------------------

    Ipv4 = 10,
    Ipv6 = 11,
    Tcp = 12,
    Udp = 13,
    Icmp = 14,
    IcmpV6 = 15,

    NetworkLayer = 20,
    AddressMetadata = 21,

    // -----------------------------------------------------------------
    // Packet action capabilities
    // -----------------------------------------------------------------

    Modification = 30,
    Drop = 31,
    Pass = 32,
    Reinjection = 33,

    // -----------------------------------------------------------------
    // Queue / lifecycle / native error capabilities
    // -----------------------------------------------------------------

    QueueControl = 40,
    HandleLifetime = 41,
    ErrorReporting = 42,

    // -----------------------------------------------------------------
    // Layer-2 / Npcap capabilities
    // -----------------------------------------------------------------

    L2Capture = 50,
    RawEthernet = 51,
    AdapterEnumeration = 52,

    // -----------------------------------------------------------------
    // WFP-specific native capabilities
    // -----------------------------------------------------------------

    WfpEngineAccess = 60,
    WfpFilters = 61,
    WfpLayers = 62,
    WfpFlows = 63,

    // -----------------------------------------------------------------
    // Windows network-state capabilities
    // -----------------------------------------------------------------

    InterfaceInfo = 70,
    RouteInfo = 71,
    NeighborInfo = 72,
    GatewayInfo = 73,

    // -----------------------------------------------------------------
    // Diagnostics / telemetry
    // -----------------------------------------------------------------

    Diagnostics = 80,
    Telemetry = 81,

    // -----------------------------------------------------------------
    // Engine-level capabilities
    //
    // These capabilities may be declared by an Engine subsystem rather
    // than by a native packet backend. They are included here so the
    // Capability Fallback Matrix (see APPLICATION_ROADMAP 0.8) can
    // express the Engine's intended coverage for every capability in a
    // single place.
    //
    // In the current architecture:
    //   - Forwarding is Engine-owned (Gateway capability subsystem).
    //   - NatState is Engine-owned (Gateway capability subsystem).
    //
    // No native packet backend currently declares these capabilities,
    // and the Engine must not assume a native backend can provide them
    // unless that backend explicitly declares them.
    // -----------------------------------------------------------------

    Forwarding = 90,
    NatState = 91,
}

impl BackendCapability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Capture => "capture",
            Self::Interception => "interception",
            Self::Filtering => "filtering",
            Self::Inspection => "inspection",
            Self::Direction => "direction",

            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::IcmpV6 => "icmpv6",

            Self::NetworkLayer => "network_layer",
            Self::AddressMetadata => "address_metadata",

            Self::Modification => "modification",
            Self::Drop => "drop",
            Self::Pass => "pass",
            Self::Reinjection => "reinjection",

            Self::QueueControl => "queue_control",
            Self::HandleLifetime => "handle_lifetime",
            Self::ErrorReporting => "error_reporting",

            Self::L2Capture => "l2_capture",
            Self::RawEthernet => "raw_ethernet",
            Self::AdapterEnumeration => "adapter_enumeration",

            Self::WfpEngineAccess => "wfp_engine_access",
            Self::WfpFilters => "wfp_filters",
            Self::WfpLayers => "wfp_layers",
            Self::WfpFlows => "wfp_flows",

            Self::InterfaceInfo => "interface_info",
            Self::RouteInfo => "route_info",
            Self::NeighborInfo => "neighbor_info",
            Self::GatewayInfo => "gateway_info",

            Self::Diagnostics => "diagnostics",
            Self::Telemetry => "telemetry",

            Self::Forwarding => "forwarding",
            Self::NatState => "nat_state",
        }
    }

    /// Stable ordering key used for deterministic serialization,
    /// logging and snapshots.
    pub const fn sort_key(self) -> u16 {
        self as u16
    }

    /// Returns true when the capability represents packet observation.
    pub const fn is_observation(self) -> bool {
        matches!(
            self,
            Self::Capture
                | Self::Interception
                | Self::Inspection
                | Self::Direction
        )
    }

    /// Returns true when the capability represents packet action.
    pub const fn is_action(self) -> bool {
        matches!(
            self,
            Self::Modification
                | Self::Drop
                | Self::Pass
                | Self::Reinjection
        )
    }

    /// Returns true when the capability represents a forwarding
    /// behavior. Forwarding is an Engine capability, not a native
    /// packet-backend capability.
    pub const fn is_engine_forwarding(self) -> bool {
        matches!(self, Self::Forwarding)
    }

    /// Returns true when the capability represents NAT runtime state
    /// handling. This is an Engine capability, not a native
    /// packet-backend capability.
    pub const fn is_engine_nat_state(self) -> bool {
        matches!(self, Self::NatState)
    }

    /// Returns true when the capability is protocol/layer related.
    pub const fn is_protocol(self) -> bool {
        matches!(
            self,
            Self::Ipv4
                | Self::Ipv6
                | Self::Tcp
                | Self::Udp
                | Self::Icmp
                | Self::IcmpV6
                | Self::NetworkLayer
                | Self::L2Capture
                | Self::RawEthernet
        )
    }

    /// Returns true when the capability is primarily network-state
    /// related.
    pub const fn is_network_state(self) -> bool {
        matches!(
            self,
            Self::InterfaceInfo
                | Self::RouteInfo
                | Self::NeighborInfo
                | Self::GatewayInfo
                | Self::AdapterEnumeration
        )
    }

    /// Returns true when the capability is diagnostic/observability
    /// related.
    pub const fn is_diagnostic(self) -> bool {
        matches!(
            self,
            Self::Diagnostics | Self::Telemetry
        )
    }

    /// Resolves a capability from its stable numeric ABI value
    /// (the same discriminant used by `sort_key`/`#[repr(u16)]`).
    /// Used by the FFI boundary to decode a Host-supplied `int`
    /// without exposing the Rust enum itself across the C ABI.
    pub const fn from_u16(value: u16) -> Option<Self> {
        Some(match value {
            0 => Self::Capture,
            1 => Self::Interception,
            2 => Self::Filtering,
            3 => Self::Inspection,
            4 => Self::Direction,
            10 => Self::Ipv4,
            11 => Self::Ipv6,
            12 => Self::Tcp,
            13 => Self::Udp,
            14 => Self::Icmp,
            15 => Self::IcmpV6,
            20 => Self::NetworkLayer,
            21 => Self::AddressMetadata,
            30 => Self::Modification,
            31 => Self::Drop,
            32 => Self::Pass,
            33 => Self::Reinjection,
            40 => Self::QueueControl,
            41 => Self::HandleLifetime,
            42 => Self::ErrorReporting,
            50 => Self::L2Capture,
            51 => Self::RawEthernet,
            52 => Self::AdapterEnumeration,
            60 => Self::WfpEngineAccess,
            61 => Self::WfpFilters,
            62 => Self::WfpLayers,
            63 => Self::WfpFlows,
            70 => Self::InterfaceInfo,
            71 => Self::RouteInfo,
            72 => Self::NeighborInfo,
            73 => Self::GatewayInfo,
            80 => Self::Diagnostics,
            81 => Self::Telemetry,
            90 => Self::Forwarding,
            91 => Self::NatState,
            _ => return None,
        })
    }

    /// Returns every known capability in deterministic order.
    ///
    /// Used by the Engine for coverage reporting and diagnostics.
    /// This does NOT represent runtime availability.
    pub const fn all_known() -> &'static [BackendCapability] {
        &[
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
            BackendCapability::L2Capture,
            BackendCapability::RawEthernet,
            BackendCapability::AdapterEnumeration,
            BackendCapability::WfpEngineAccess,
            BackendCapability::WfpFilters,
            BackendCapability::WfpLayers,
            BackendCapability::WfpFlows,
            BackendCapability::InterfaceInfo,
            BackendCapability::RouteInfo,
            BackendCapability::NeighborInfo,
            BackendCapability::GatewayInfo,
            BackendCapability::Diagnostics,
            BackendCapability::Telemetry,
            BackendCapability::Forwarding,
            BackendCapability::NatState,
        ]
    }
}

/// Set of capabilities declared for a backend.
///
/// CapabilitySet is a value object. It does not know:
/// - whether the backend is running
/// - whether the backend is healthy
/// - whether a capability is currently available
/// - what traffic scope the capability applies to
/// - whether Host policy permits its use
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapabilitySet {
    capabilities: HashSet<BackendCapability>,
}

impl CapabilitySet {
    pub fn new() -> Self {
        Self {
            capabilities: HashSet::new(),
        }
    }

    pub fn from(
        capabilities: impl IntoIterator<Item = BackendCapability>,
    ) -> Self {
        let mut set = Self::new();

        for capability in capabilities {
            set.insert(capability);
        }

        set
    }

    pub fn insert(
        &mut self,
        capability: BackendCapability,
    ) -> bool {
        self.capabilities.insert(capability)
    }

    pub fn remove(
        &mut self,
        capability: BackendCapability,
    ) -> bool {
        self.capabilities.remove(&capability)
    }

    pub fn contains(
        &self,
        capability: BackendCapability,
    ) -> bool {
        self.capabilities.contains(&capability)
    }

    pub fn is_empty(&self) -> bool {
        self.capabilities.is_empty()
    }

    pub fn len(&self) -> usize {
        self.capabilities.len()
    }

    pub fn clear(&mut self) {
        self.capabilities.clear();
    }

    pub fn iter(
        &self,
    ) -> impl Iterator<Item = &BackendCapability> {
        self.capabilities.iter()
    }

    /// Returns a deterministic capability list.
    pub fn to_vec(&self) -> Vec<BackendCapability> {
        let mut result: Vec<_> =
            self.capabilities.iter().copied().collect();

        result.sort_by_key(|capability| capability.sort_key());

        result
    }

    pub fn supports_all(
        &self,
        required: &[BackendCapability],
    ) -> bool {
        required
            .iter()
            .all(|capability| self.contains(*capability))
    }

    pub fn supports_any(
        &self,
        required: &[BackendCapability],
    ) -> bool {
        required
            .iter()
            .any(|capability| self.contains(*capability))
    }
}

/// A capability requirement supplied to the Engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityRequirement {
    pub capability: BackendCapability,
    pub required: bool,
}

impl CapabilityRequirement {
    pub const fn required(
        capability: BackendCapability,
    ) -> Self {
        Self {
            capability,
            required: true,
        }
    }

    pub const fn optional(
        capability: BackendCapability,
    ) -> Self {
        Self {
            capability,
            required: false,
        }
    }
}

/// Result of validating a capability requirement set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityCheck {
    pub supported: bool,
    pub missing_required: Vec<BackendCapability>,
    pub missing_optional: Vec<BackendCapability>,
}

impl CapabilityCheck {
    pub fn is_satisfied(&self) -> bool {
        self.missing_required.is_empty()
    }

    pub fn has_optional_degradation(&self) -> bool {
        !self.missing_optional.is_empty()
    }
}

/// Checks a capability set against a requirement list.
///
/// Missing optional capabilities do not fail the check.
///
/// No backend is selected here and no native operation is performed.
pub fn check_requirements(
    available: &CapabilitySet,
    requirements: &[CapabilityRequirement],
) -> CapabilityCheck {
    let mut missing_required = Vec::new();
    let mut missing_optional = Vec::new();

    for requirement in requirements {
        if available.contains(requirement.capability) {
            continue;
        }

        if requirement.required {
            missing_required.push(requirement.capability);
        } else {
            missing_optional.push(requirement.capability);
        }
    }

    missing_required
        .sort_by_key(|capability| capability.sort_key());

    missing_optional
        .sort_by_key(|capability| capability.sort_key());

    CapabilityCheck {
        supported: missing_required.is_empty(),
        missing_required,
        missing_optional,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_empty_capability_set() {
        let set = CapabilitySet::new();

        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn inserts_capability() {
        let mut set = CapabilitySet::new();

        assert!(
            set.insert(
                BackendCapability::Capture
            )
        );

        assert!(
            set.contains(
                BackendCapability::Capture
            )
        );

        assert_eq!(set.len(), 1);
    }

    #[test]
    fn duplicate_capability_is_not_inserted_twice() {
        let mut set = CapabilitySet::new();

        assert!(
            set.insert(
                BackendCapability::Capture
            )
        );

        assert!(
            !set.insert(
                BackendCapability::Capture
            )
        );

        assert_eq!(set.len(), 1);
    }

    #[test]
    fn removes_capability() {
        let mut set = CapabilitySet::new();

        set.insert(
            BackendCapability::Capture
        );

        assert!(
            set.remove(
                BackendCapability::Capture
            )
        );

        assert!(
            !set.contains(
                BackendCapability::Capture
            )
        );
    }

    #[test]
    fn supports_all_capabilities() {
        let set = CapabilitySet::from([
            BackendCapability::Capture,
            BackendCapability::Reinjection,
        ]);

        assert!(
            set.supports_all(&[
                BackendCapability::Capture,
                BackendCapability::Reinjection,
            ])
        );
    }

    #[test]
    fn supports_any_capability() {
        let set = CapabilitySet::from([
            BackendCapability::Capture,
        ]);

        assert!(
            set.supports_any(&[
                BackendCapability::Reinjection,
                BackendCapability::Capture,
            ])
        );
    }

    #[test]
    fn check_requirements_detects_missing_required() {
        let available = CapabilitySet::from([
            BackendCapability::Capture,
        ]);

        let requirements = [
            CapabilityRequirement::required(
                BackendCapability::Capture,
            ),
            CapabilityRequirement::required(
                BackendCapability::Reinjection,
            ),
        ];

        let result =
            check_requirements(
                &available,
                &requirements,
            );

        assert!(!result.supported);

        assert_eq!(
            result.missing_required,
            vec![
                BackendCapability::Reinjection
            ]
        );
    }

    #[test]
    fn optional_capability_does_not_fail_check() {
        let available = CapabilitySet::from([
            BackendCapability::Capture,
        ]);

        let requirements = [
            CapabilityRequirement::required(
                BackendCapability::Capture,
            ),
            CapabilityRequirement::optional(
                BackendCapability::Diagnostics,
            ),
        ];

        let result =
            check_requirements(
                &available,
                &requirements,
            );

        assert!(result.is_satisfied());

        assert_eq!(
            result.missing_optional,
            vec![
                BackendCapability::Diagnostics
            ]
        );

        assert!(
            result.has_optional_degradation()
        );
    }

    #[test]
    fn capability_names_are_stable() {
        assert_eq!(
            BackendCapability::Capture.as_str(),
            "capture"
        );

        assert_eq!(
            BackendCapability::L2Capture.as_str(),
            "l2_capture"
        );

        assert_eq!(
            BackendCapability::RouteInfo.as_str(),
            "route_info"
        );

        assert_eq!(
            BackendCapability::Reinjection.as_str(),
            "reinjection"
        );

        assert_eq!(
            BackendCapability::Forwarding.as_str(),
            "forwarding"
        );

        assert_eq!(
            BackendCapability::NatState.as_str(),
            "nat_state"
        );
    }

    #[test]
    fn capability_categories_are_correct() {
        assert!(
            BackendCapability::Capture
                .is_observation()
        );

        assert!(
            BackendCapability::Modification
                .is_action()
        );

        assert!(
            BackendCapability::Tcp
                .is_protocol()
        );

        assert!(
            BackendCapability::RouteInfo
                .is_network_state()
        );

        assert!(
            BackendCapability::Telemetry
                .is_diagnostic()
        );

        assert!(
            BackendCapability::Forwarding
                .is_engine_forwarding()
        );

        assert!(
            BackendCapability::NatState
                .is_engine_nat_state()
        );
    }

    #[test]
    fn capability_vector_is_deterministic() {
        let set = CapabilitySet::from([
            BackendCapability::Udp,
            BackendCapability::Capture,
            BackendCapability::Ipv4,
            BackendCapability::Drop,
        ]);

        assert_eq!(
            set.to_vec(),
            vec![
                BackendCapability::Capture,
                BackendCapability::Ipv4,
                BackendCapability::Udp,
                BackendCapability::Drop,
            ]
        );
    }

    #[test]
    fn empty_requirements_are_satisfied() {
        let set = CapabilitySet::new();

        let result =
            check_requirements(
                &set,
                &[],
            );

        assert!(result.supported);
        assert!(
            result.missing_required.is_empty()
        );
        assert!(
            result.missing_optional.is_empty()
        );
    }

    #[test]
    fn forward_and_nat_round_trip_from_u16() {
        assert_eq!(
            BackendCapability::from_u16(90),
            Some(BackendCapability::Forwarding)
        );

        assert_eq!(
            BackendCapability::from_u16(91),
            Some(BackendCapability::NatState)
        );
    }

    #[test]
    fn all_known_is_deterministic_and_complete() {
        let all = BackendCapability::all_known();
        assert!(!all.is_empty());

        // Every known capability must round-trip through from_u16.
        for capability in all {
            assert_eq!(
                BackendCapability::from_u16(capability.sort_key()),
                Some(*capability)
            );
        }

        // No duplicate entries.
        let mut keys: Vec<u16> =
            all.iter().map(|c| c.sort_key()).collect();
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), all.len());
    }
}