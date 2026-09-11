#![forbid(unsafe_code)]

use crate::BackendCapability;

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

/// Read-only inventory of the capabilities declared by registered
/// backends.
///
/// CapabilityRegistry intentionally does NOT own:
/// - backend lifecycle
/// - backend health
/// - backend availability
/// - native backend execution
/// - packet policy
/// - filtering policy
/// - DROP/PASS policy
/// - routing/NAT/Gateway policy
/// - backend conflict resolution
///
/// In particular, capability overlap is NOT a conflict.
///
/// WFP and WinDivert may both advertise capabilities such as
/// Filtering, Interception, Modification, or Reinjection while
/// operating on different layers, directions, filters, interfaces,
/// or traffic scopes.
///
/// Scope/resource conflict detection belongs to the Engine-level
/// coordination layer.
#[derive(Debug, Default)]
pub struct CapabilityRegistry {
    capabilities: RwLock<HashMap<String, HashSet<BackendCapability>>>,
}

impl CapabilityRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers or replaces the capability snapshot for a backend.
    ///
    /// The registry stores a complete declaration for the backend.
    /// A subsequent registration replaces the previous capability
    /// set instead of merging with stale capabilities.
    ///
    /// Returns `false` when the backend name is invalid.
    pub fn register_backend(
        &self,
        backend_name: impl Into<String>,
        capabilities: impl IntoIterator<Item = BackendCapability>,
    ) -> bool {
        let name = normalize_backend_name(backend_name.into());

        if name.is_empty() {
            return false;
        }

        let capability_set: HashSet<BackendCapability> =
            capabilities.into_iter().collect();

        match self.capabilities.write() {
            Ok(mut registry) => {
                registry.insert(name, capability_set);
                true
            }
            Err(_) => false,
        }
    }

    /// Removes a backend and all of its declared capabilities.
    ///
    /// Returns `true` only when the backend existed.
    pub fn unregister_backend(&self, backend_name: &str) -> bool {
        let name = normalize_backend_name(backend_name.to_owned());

        if name.is_empty() {
            return false;
        }

        self.capabilities
            .write()
            .map(|mut registry| registry.remove(&name).is_some())
            .unwrap_or(false)
    }

    pub fn contains_backend(&self, backend_name: &str) -> bool {
        let name = normalize_backend_name(backend_name.to_owned());

        if name.is_empty() {
            return false;
        }

        self.capabilities
            .read()
            .map(|registry| registry.contains_key(&name))
            .unwrap_or(false)
    }

    /// Returns whether the backend declares the requested capability.
    ///
    /// This is a static capability query only.
    ///
    /// `true` does NOT mean the backend is currently:
    /// - running
    /// - healthy
    /// - available
    /// - permitted
    /// - selected for execution
    pub fn supports(
        &self,
        backend_name: &str,
        capability: BackendCapability,
    ) -> bool {
        let name = normalize_backend_name(backend_name.to_owned());

        if name.is_empty() {
            return false;
        }

        self.capabilities
            .read()
            .map(|registry| {
                registry
                    .get(&name)
                    .map(|capabilities| capabilities.contains(&capability))
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    }

    /// Returns the complete declared capability set for a backend.
    ///
    /// The result is deterministic.
    pub fn capabilities(
        &self,
        backend_name: &str,
    ) -> Vec<BackendCapability> {
        let name = normalize_backend_name(backend_name.to_owned());

        if name.is_empty() {
            return Vec::new();
        }

        self.capabilities
            .read()
            .ok()
            .and_then(|registry| registry.get(&name).map(sorted_capabilities))
            .unwrap_or_default()
    }

    /// Returns all registered backends declaring a capability.
    ///
    /// The result is sorted by backend name for deterministic selection
    /// and reproducible tests.
    ///
    /// This method intentionally does not inspect backend lifecycle
    /// or health.
    pub fn backends_with(
        &self,
        capability: BackendCapability,
    ) -> Vec<String> {
        self.capabilities
            .read()
            .map(|registry| {
                let mut result: Vec<String> = registry
                    .iter()
                    .filter_map(|(name, capabilities)| {
                        capabilities
                            .contains(&capability)
                            .then(|| name.clone())
                    })
                    .collect();

                result.sort_unstable();
                result
            })
            .unwrap_or_default()
    }

    /// Number of registered backend capability records.
    ///
    /// This is the number of backend identities, not the number of
    /// individual capability declarations.
    pub fn backend_count(&self) -> usize {
        self.capabilities
            .read()
            .map(|registry| registry.len())
            .unwrap_or(0)
    }

    /// Number of declared capabilities for one backend.
    pub fn capability_count(
        &self,
        backend_name: &str,
    ) -> usize {
        let name = normalize_backend_name(backend_name.to_owned());

        if name.is_empty() {
            return 0;
        }

        self.capabilities
            .read()
            .ok()
            .and_then(|registry| {
                registry.get(&name).map(HashSet::len)
            })
            .unwrap_or(0)
    }

    /// Removes every registered backend from the registry.
    ///
    /// This affects capability metadata only.
    /// It does not stop or unload native backends.
    pub fn clear(&self) {
        if let Ok(mut registry) = self.capabilities.write() {
            registry.clear();
        }
    }

    /// Returns all registered backend names in deterministic order.
    pub fn backend_names(&self) -> Vec<String> {
        self.capabilities
            .read()
            .map(|registry| {
                let mut names: Vec<String> =
                    registry.keys().cloned().collect();

                names.sort_unstable();
                names
            })
            .unwrap_or_default()
    }

    /// Returns a deterministic snapshot of the registry.
    ///
    /// The inner capability vectors are sorted and the returned map
    /// contains only the current authoritative capability declarations.
    pub fn snapshot(
        &self,
    ) -> HashMap<String, Vec<BackendCapability>> {
        self.capabilities
            .read()
            .map(|registry| {
                registry
                    .iter()
                    .map(|(name, capabilities)| {
                        (
                            name.clone(),
                            sorted_capabilities(capabilities),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn normalize_backend_name(name: String) -> String {
    name.trim().to_owned()
}

fn sorted_capabilities(
    capabilities: &HashSet<BackendCapability>,
) -> Vec<BackendCapability> {
    let mut result: Vec<BackendCapability> =
        capabilities.iter().copied().collect();

    result.sort_by_key(|capability| capability_sort_key(*capability));

    result
}

fn capability_sort_key(
    capability: BackendCapability,
) -> u8 {
    match capability {
        BackendCapability::Capture => 0,
        BackendCapability::Interception => 1,
        BackendCapability::Filtering => 2,
        BackendCapability::Inspection => 3,
        BackendCapability::Direction => 4,
        BackendCapability::Ipv4 => 5,
        BackendCapability::Ipv6 => 6,
        BackendCapability::Tcp => 7,
        BackendCapability::Udp => 8,
        BackendCapability::Icmp => 9,
        BackendCapability::IcmpV6 => 10,
        BackendCapability::NetworkLayer => 11,
        BackendCapability::AddressMetadata => 12,
        BackendCapability::Modification => 13,
        BackendCapability::Drop => 14,
        BackendCapability::Pass => 15,
        BackendCapability::Reinjection => 16,
        BackendCapability::QueueControl => 17,
        BackendCapability::HandleLifetime => 18,
        BackendCapability::ErrorReporting => 19,
        BackendCapability::L2Capture => 20,
        BackendCapability::RawEthernet => 21,
        BackendCapability::AdapterEnumeration => 22,
        BackendCapability::WfpEngineAccess => 23,
        BackendCapability::WfpFilters => 24,
        BackendCapability::WfpLayers => 25,
        BackendCapability::WfpFlows => 26,
        BackendCapability::InterfaceInfo => 27,
        BackendCapability::RouteInfo => 28,
        BackendCapability::NeighborInfo => 29,
        BackendCapability::GatewayInfo => 30,
        BackendCapability::Diagnostics => 31,
        BackendCapability::Telemetry => 32,
		BackendCapability::Forwarding => 33,
        BackendCapability::NatState => 34,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_and_queries_capabilities() {
        let registry = CapabilityRegistry::new();

        assert!(registry.register_backend(
            "windivert",
            [
                BackendCapability::Capture,
                BackendCapability::Interception,
                BackendCapability::Ipv4,
            ],
        ));

        assert!(registry.contains_backend("windivert"));

        assert!(
            registry.supports(
                "windivert",
                BackendCapability::Interception
            )
        );

        assert!(
            !registry.supports(
                "windivert",
                BackendCapability::L2Capture
            )
        );
    }

    #[test]
    fn duplicate_capabilities_are_deduplicated() {
        let registry = CapabilityRegistry::new();

        assert!(registry.register_backend(
            "test",
            [
                BackendCapability::Capture,
                BackendCapability::Capture,
                BackendCapability::Ipv4,
            ],
        ));

        assert_eq!(registry.capability_count("test"), 2);
    }

    #[test]
    fn backend_lookup_is_sorted() {
        let registry = CapabilityRegistry::new();

        assert!(registry.register_backend(
            "test",
            [
                BackendCapability::Ipv4,
                BackendCapability::Capture,
                BackendCapability::Udp,
            ],
        ));

        assert_eq!(
            registry.capabilities("test"),
            vec![
                BackendCapability::Capture,
                BackendCapability::Ipv4,
                BackendCapability::Udp,
            ]
        );
    }

    #[test]
    fn finds_backends_by_capability() {
        let registry = CapabilityRegistry::new();

        assert!(registry.register_backend(
            "wfp",
            [BackendCapability::Filtering],
        ));

        assert!(registry.register_backend(
            "windivert",
            [
                BackendCapability::Filtering,
                BackendCapability::Interception,
            ],
        ));

        assert!(registry.register_backend(
            "npcap",
            [BackendCapability::L2Capture],
        ));

        assert_eq!(
            registry.backends_with(BackendCapability::Filtering),
            vec![
                "windivert".to_string(),
                "wfp".to_string(),
            ]
        );
    }

    #[test]
    fn unregister_removes_backend() {
        let registry = CapabilityRegistry::new();

        assert!(registry.register_backend(
            "test",
            [BackendCapability::Capture],
        ));

        assert!(registry.unregister_backend("test"));
        assert!(!registry.contains_backend("test"));
        assert!(!registry.unregister_backend("test"));
    }

    #[test]
    fn unknown_backend_returns_empty() {
        let registry = CapabilityRegistry::new();

        assert!(
            registry.capabilities("missing").is_empty()
        );

        assert_eq!(
            registry.capability_count("missing"),
            0
        );

        assert!(
            !registry.supports(
                "missing",
                BackendCapability::Capture
            )
        );
    }

    #[test]
    fn snapshot_contains_all_backends() {
        let registry = CapabilityRegistry::new();

        assert!(registry.register_backend(
            "wfp",
            [BackendCapability::Filtering],
        ));

        assert!(registry.register_backend(
            "npcap",
            [BackendCapability::L2Capture],
        ));

        let snapshot = registry.snapshot();

        assert_eq!(snapshot.len(), 2);

        assert_eq!(
            snapshot["wfp"],
            vec![BackendCapability::Filtering]
        );

        assert_eq!(
            snapshot["npcap"],
            vec![BackendCapability::L2Capture]
        );
    }

    #[test]
    fn clear_removes_everything() {
        let registry = CapabilityRegistry::new();

        assert!(registry.register_backend(
            "wfp",
            [BackendCapability::Filtering],
        ));

        assert!(registry.register_backend(
            "npcap",
            [BackendCapability::L2Capture],
        ));

        registry.clear();

        assert_eq!(registry.backend_count(), 0);
        assert!(registry.backend_names().is_empty());
        assert!(registry.snapshot().is_empty());
    }

    #[test]
    fn empty_backend_name_is_rejected() {
        let registry = CapabilityRegistry::new();

        assert!(!registry.register_backend(
            "   ",
            [BackendCapability::Capture],
        ));

        assert_eq!(registry.backend_count(), 0);
    }

    #[test]
    fn backend_names_are_normalized() {
        let registry = CapabilityRegistry::new();

        assert!(registry.register_backend(
            "  windivert  ",
            [BackendCapability::Capture],
        ));

        assert!(registry.contains_backend("windivert"));
        assert!(!registry.contains_backend("  "));

        assert_eq!(
            registry.backend_names(),
            vec!["windivert".to_string()]
        );
    }

    #[test]
    fn duplicate_registration_replaces_stale_capabilities() {
        let registry = CapabilityRegistry::new();

        assert!(registry.register_backend(
            "wfp",
            [
                BackendCapability::Filtering,
                BackendCapability::Interception,
            ],
        ));

        assert!(registry.register_backend(
            "wfp",
            [BackendCapability::Capture],
        ));

        assert_eq!(
            registry.capabilities("wfp"),
            vec![BackendCapability::Capture]
        );

        assert!(
            !registry.supports(
                "wfp",
                BackendCapability::Filtering
            )
        );
    }

    #[test]
    fn capability_overlap_is_allowed() {
        let registry = CapabilityRegistry::new();

        assert!(registry.register_backend(
            "wfp",
            [
                BackendCapability::Filtering,
                BackendCapability::Interception,
            ],
        ));

        assert!(registry.register_backend(
            "windivert",
            [
                BackendCapability::Filtering,
                BackendCapability::Interception,
            ],
        ));

        assert_eq!(
            registry.backends_with(
                BackendCapability::Filtering
            ),
            vec![
                "windivert".to_string(),
                "wfp".to_string(),
            ]
        );
    }

    #[test]
    fn empty_capability_set_still_registers_backend() {
        let registry = CapabilityRegistry::new();

        assert!(registry.register_backend(
            "test",
            std::iter::empty::<BackendCapability>(),
        ));

        assert!(registry.contains_backend("test"));
        assert_eq!(registry.capability_count("test"), 0);
        assert_eq!(
            registry.backend_names(),
            vec!["test".to_string()]
        );
    }
}