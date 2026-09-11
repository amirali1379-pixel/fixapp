#![forbid(unsafe_code)]

use crate::BackendCapability;

use std::collections::HashMap;

/// Runtime state of the failover coordinator.
///
/// This is NOT the lifecycle state of a backend.
///
/// Backend lifecycle belongs to `BackendRuntimeState` and
/// `BackendManager`.
///
/// This state only describes whether failover coordination itself
/// is enabled and usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailoverState {
    /// Failover coordination is disabled.
    Disabled,

    /// Failover coordinator is configured and ready.
    Ready,

    /// A fallback has currently been selected.
    Active,

    /// Failover coordination is operating with reduced capability.
    Degraded,

    /// Failover coordination cannot currently provide a fallback.
    Failed,
}

impl FailoverState {
    pub fn is_available(self) -> bool {
        matches!(
            self,
            Self::Ready
                | Self::Active
                | Self::Degraded
        )
    }

    pub fn can_activate(self) -> bool {
        matches!(
            self,
            Self::Ready
                | Self::Degraded
        )
    }

    pub fn is_failed(self) -> bool {
        self == Self::Failed
    }

    pub fn is_disabled(self) -> bool {
        self == Self::Disabled
    }
}

/// A backend candidate for failover selection.
///
/// IMPORTANT:
/// This struct does NOT own backend lifecycle or health.
///
/// `priority` expresses failover preference only:
/// lower value = higher preference.
///
/// Capability information is optional metadata supplied by the
/// Engine/BackendManager. It must not be treated as authoritative
/// runtime capability state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailoverBackend {
    pub name: String,
    pub priority: u32,
    capabilities: Vec<BackendCapability>,
}

impl FailoverBackend {
    pub fn new(
        name: impl Into<String>,
        priority: u32,
    ) -> Option<Self> {
        let name = name.into().trim().to_owned();

        if name.is_empty() {
            return None;
        }

        Some(Self {
            name,
            priority,
            capabilities: Vec::new(),
        })
    }

    /// Adds a capability to the local candidate metadata.
    ///
    /// This does not alter the authoritative BackendCapability
    /// declaration held by `CapabilityRegistry`.
    pub fn add_capability(
        &mut self,
        capability: BackendCapability,
    ) {
        if !self.capabilities.contains(&capability) {
            self.capabilities.push(capability);

            self.capabilities
                .sort_by_key(|capability| {
                    capability_sort_key(*capability)
                });
        }
    }

    pub fn supports(
        &self,
        capability: BackendCapability,
    ) -> bool {
        self.capabilities.contains(&capability)
    }

    pub fn capabilities(
        &self,
    ) -> &[BackendCapability] {
        &self.capabilities
    }
}

/// Errors produced by failover coordination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailoverError {
    /// No registered candidate satisfies the requested capability.
    CapabilityUnavailable,

    /// Candidates exist but none is currently eligible.
    NoBackendAvailable,

    /// Backend name is invalid or unknown.
    InvalidBackend,

    /// Failover coordinator is not currently allowed to activate.
    InvalidState,

    /// Requested backend is already the active candidate.
    AlreadyActive,
}

/// Lightweight failover coordinator.
///
/// Ownership boundaries:
///
/// ```text
/// CapabilityRegistry
///     ↓
/// declared capabilities
///
/// BackendManager
///     ↓
/// lifecycle + health + availability
///
/// FailoverManager
///     ↓
/// preference + candidate ordering + active selection
///
/// Engine
///     ↓
/// actual capability negotiation + native execution
/// ```
///
/// FailoverManager does NOT:
/// - start native backends
/// - stop native backends
/// - modify backend lifecycle
/// - modify backend health
/// - execute packet actions
/// - perform DROP/PASS/MODIFY/REINJECT
/// - perform routing/NAT/Gateway policy
/// - resolve traffic-scope conflicts
#[derive(Debug)]
pub struct FailoverManager {
    backends: Vec<FailoverBackend>,
    active_backend: Option<String>,
    state: FailoverState,

    /// Optional per-backend capability metadata.
    ///
    /// This exists only to support local candidate filtering.
    /// BackendManager/CapabilityRegistry remain authoritative.
    capability_index:
        HashMap<String, Vec<BackendCapability>>,
}

impl FailoverManager {
    pub fn new() -> Self {
        Self {
            backends: Vec::new(),
            active_backend: None,
            state: FailoverState::Ready,
            capability_index: HashMap::new(),
        }
    }

    pub fn state(&self) -> FailoverState {
        self.state
    }

    pub fn register(
        &mut self,
        backend: FailoverBackend,
    ) -> Result<(), FailoverError> {
        if backend.name.trim().is_empty() {
            return Err(FailoverError::InvalidBackend);
        }

        if self.backends.iter().any(|existing| {
            existing.name == backend.name
        }) {
            return Err(FailoverError::InvalidBackend);
        }

        let name = backend.name.clone();
        let capabilities =
            backend.capabilities.clone();

        self.backends.push(backend);

        self.capability_index
            .insert(name, capabilities);

        self.sort_by_priority();

        if self.state == FailoverState::Failed {
            self.state = FailoverState::Ready;
        }

        Ok(())
    }

    /// Removes a candidate from failover coordination.
    ///
    /// This does not stop or unregister the actual backend from
    /// BackendManager.
    pub fn unregister(
        &mut self,
        name: &str,
    ) -> Result<(), FailoverError> {
        let position = self
            .backends
            .iter()
            .position(|backend| backend.name == name)
            .ok_or(FailoverError::InvalidBackend)?;

        if self.active_backend.as_deref() == Some(name) {
            self.active_backend = None;
            self.state = FailoverState::Ready;
        }

        self.backends.remove(position);
        self.capability_index.remove(name);

        Ok(())
    }

    /// Selects the highest-priority eligible candidate.
    ///
    /// Lower priority value wins.
    ///
    /// Selection does not activate or start the backend.
    pub fn select(
        &self,
        capability: BackendCapability,
    ) -> Result<&FailoverBackend, FailoverError> {
        let candidates = self
            .backends
            .iter()
            .filter(|backend| {
                backend.supports(capability)
            });

        let selected = candidates
            .min_by(|left, right| {
                left.priority
                    .cmp(&right.priority)
                    .then_with(|| {
                        left.name.cmp(&right.name)
                    })
            });

        selected.ok_or(
            FailoverError::CapabilityUnavailable
        )
    }

    /// Selects the best candidate and marks the selection as active.
    ///
    /// This does NOT start, stop, or reconfigure the native backend.
    ///
    /// The Engine must perform actual backend capability/lifecycle
    /// validation before executing traffic through the selected backend.
    pub fn activate_best(
        &mut self,
        capability: BackendCapability,
    ) -> Result<String, FailoverError> {
        if !self.state.can_activate() {
            return Err(FailoverError::InvalidState);
        }

        let selected_name = self
            .backends
            .iter()
            .filter(|backend| {
                backend.supports(capability)
            })
            .min_by(|left, right| {
                left.priority
                    .cmp(&right.priority)
                    .then_with(|| {
                        left.name.cmp(&right.name)
                    })
            })
            .map(|backend| backend.name.clone())
            .ok_or(
                FailoverError::CapabilityUnavailable
            )?;

        if self.active_backend.as_deref()
            == Some(selected_name.as_str())
        {
            return Err(
                FailoverError::AlreadyActive
            );
        }

        self.active_backend =
            Some(selected_name.clone());

        self.state = FailoverState::Active;

        Ok(selected_name)
    }

    /// Clears the current active selection without modifying backend
    /// lifecycle.
    pub fn deactivate(
        &mut self,
    ) {
        self.active_backend = None;

        if self.state != FailoverState::Disabled {
            self.state = FailoverState::Ready;
        }
    }

    /// Marks the failover coordinator degraded.
    ///
    /// This does not modify backend health.
    pub fn mark_degraded(&mut self) {
        if self.state != FailoverState::Disabled {
            self.state = FailoverState::Degraded;
        }
    }

    /// Marks the failover coordinator failed.
    ///
    /// The individual backend states remain owned by BackendManager.
    pub fn mark_failed(&mut self) {
        self.state = FailoverState::Failed;
        self.active_backend = None;
    }

    pub fn mark_ready(&mut self) {
        if self.state != FailoverState::Disabled {
            self.state = FailoverState::Ready;
        }
    }

    pub fn disable(&mut self) {
        self.state = FailoverState::Disabled;
        self.active_backend = None;
    }

    pub fn active_backend(&self) -> Option<&str> {
        self.active_backend.as_deref()
    }

    pub fn get(
        &self,
        name: &str,
    ) -> Option<&FailoverBackend> {
        self.backends
            .iter()
            .find(|backend| {
                backend.name == name
            })
    }

    pub fn get_mut(
        &mut self,
        name: &str,
    ) -> Option<&mut FailoverBackend> {
        self.backends
            .iter_mut()
            .find(|backend| {
                backend.name == name
            })
    }

    pub fn backends(&self) -> &[FailoverBackend] {
        &self.backends
    }

    pub fn clear(&mut self) {
        self.backends.clear();
        self.capability_index.clear();
        self.active_backend = None;
        self.state = FailoverState::Ready;
    }

    pub fn len(&self) -> usize {
        self.backends.len()
    }

    pub fn is_empty(&self) -> bool {
        self.backends.is_empty()
    }

    /// Returns candidates supporting the requested capability.
    ///
    /// The result is ordered by:
    ///
    /// 1. priority
    /// 2. backend name
    ///
    /// This makes failover decisions deterministic.
    pub fn candidates(
        &self,
        capability: BackendCapability,
    ) -> Vec<&FailoverBackend> {
        let mut candidates: Vec<&FailoverBackend> =
            self.backends
                .iter()
                .filter(|backend| {
                    backend.supports(capability)
                })
                .collect();

        candidates.sort_by(|left, right| {
            left.priority
                .cmp(&right.priority)
                .then_with(|| {
                    left.name.cmp(&right.name)
                })
        });

        candidates
    }

    /// Returns the registered candidate names in deterministic order.
    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .backends
            .iter()
            .map(|backend| backend.name.clone())
            .collect();

        names.sort_unstable();

        names
    }

    fn sort_by_priority(&mut self) {
        self.backends.sort_by(|left, right| {
            left.priority
                .cmp(&right.priority)
                .then_with(|| {
                    left.name.cmp(&right.name)
                })
        });
    }
}

impl Default for FailoverManager {
    fn default() -> Self {
        Self::new()
    }
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
		BackendCapability::Forwarding => 33,   // ← اضافه کن
        BackendCapability::NatState => 34,     // ← اضافه کن
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_backend() {
        let backend =
            FailoverBackend::new("npcap", 10);

        assert!(backend.is_some());
        assert_eq!(
            backend.unwrap().name,
            "npcap"
        );
    }

    #[test]
    fn trims_backend_name() {
        let backend =
            FailoverBackend::new(
                "  npcap  ",
                10,
            )
            .unwrap();

        assert_eq!(
            backend.name,
            "npcap"
        );
    }

    #[test]
    fn rejects_empty_backend_name() {
        assert!(
            FailoverBackend::new("", 1).is_none()
        );

        assert!(
            FailoverBackend::new(
                "   ",
                1
            )
            .is_none()
        );
    }

    #[test]
    fn backend_capability_can_be_added() {
        let mut backend =
            FailoverBackend::new(
                "npcap",
                10,
            )
            .unwrap();

        backend.add_capability(
            BackendCapability::Capture
        );

        assert!(
            backend.supports(
                BackendCapability::Capture
            )
        );
    }

    #[test]
    fn duplicate_capabilities_are_ignored() {
        let mut backend =
            FailoverBackend::new(
                "npcap",
                10,
            )
            .unwrap();

        backend.add_capability(
            BackendCapability::Capture
        );

        backend.add_capability(
            BackendCapability::Capture
        );

        assert_eq!(
            backend.capabilities().len(),
            1
        );
    }

    #[test]
    fn manager_registers_backend() {
        let mut manager =
            FailoverManager::new();

        manager
            .register(
                FailoverBackend::new(
                    "npcap",
                    10,
                )
                .unwrap(),
            )
            .unwrap();

        assert_eq!(
            manager.len(),
            1
        );

        assert_eq!(
            manager.state(),
            FailoverState::Ready
        );
    }

    #[test]
    fn duplicate_backend_is_rejected() {
        let mut manager =
            FailoverManager::new();

        manager
            .register(
                FailoverBackend::new(
                    "npcap",
                    10,
                )
                .unwrap(),
            )
            .unwrap();

        assert_eq!(
            manager.register(
                FailoverBackend::new(
                    "npcap",
                    20,
                )
                .unwrap(),
            ),
            Err(
                FailoverError::InvalidBackend
            )
        );
    }

    #[test]
    fn select_uses_priority() {
        let mut manager =
            FailoverManager::new();

        let mut slow =
            FailoverBackend::new(
                "slow",
                20,
            )
            .unwrap();

        slow.add_capability(
            BackendCapability::Capture
        );

        let mut fast =
            FailoverBackend::new(
                "fast",
                10,
            )
            .unwrap();

        fast.add_capability(
            BackendCapability::Capture
        );

        manager.register(slow).unwrap();
        manager.register(fast).unwrap();

        let selected =
            manager
                .select(
                    BackendCapability::Capture
                )
                .unwrap();

        assert_eq!(
            selected.name,
            "fast"
        );
    }

    #[test]
    fn equal_priority_is_deterministic() {
        let mut manager =
            FailoverManager::new();

        let mut z =
            FailoverBackend::new(
                "z-backend",
                10,
            )
            .unwrap();

        z.add_capability(
            BackendCapability::Capture
        );

        let mut a =
            FailoverBackend::new(
                "a-backend",
                10,
            )
            .unwrap();

        a.add_capability(
            BackendCapability::Capture
        );

        manager.register(z).unwrap();
        manager.register(a).unwrap();

        let selected =
            manager
                .select(
                    BackendCapability::Capture
                )
                .unwrap();

        assert_eq!(
            selected.name,
            "a-backend"
        );
    }

    #[test]
    fn activate_best_sets_active_backend() {
        let mut manager =
            FailoverManager::new();

        let mut backend =
            FailoverBackend::new(
                "npcap",
                10,
            )
            .unwrap();

        backend.add_capability(
            BackendCapability::Capture
        );

        manager.register(backend).unwrap();

        let name =
            manager
                .activate_best(
                    BackendCapability::Capture
                )
                .unwrap();

        assert_eq!(name, "npcap");

        assert_eq!(
            manager.active_backend(),
            Some("npcap")
        );

        assert_eq!(
            manager.state(),
            FailoverState::Active
        );
    }

    #[test]
    fn activating_same_backend_is_rejected() {
        let mut manager =
            FailoverManager::new();

        let mut backend =
            FailoverBackend::new(
                "npcap",
                1,
            )
            .unwrap();

        backend.add_capability(
            BackendCapability::Capture
        );

        manager.register(backend).unwrap();

        manager
            .activate_best(
                BackendCapability::Capture
            )
            .unwrap();

        assert_eq!(
            manager.activate_best(
                BackendCapability::Capture
            ),
            Err(
                FailoverError::AlreadyActive
            )
        );
    }

    #[test]
    fn deactivate_clears_active_selection() {
        let mut manager =
            FailoverManager::new();

        let mut backend =
            FailoverBackend::new(
                "npcap",
                1,
            )
            .unwrap();

        backend.add_capability(
            BackendCapability::Capture
        );

        manager.register(backend).unwrap();

        manager
            .activate_best(
                BackendCapability::Capture
            )
            .unwrap();

        manager.deactivate();

        assert_eq!(
            manager.active_backend(),
            None
        );

        assert_eq!(
            manager.state(),
            FailoverState::Ready
        );
    }

    #[test]
    fn capability_unavailable_is_distinct() {
        let mut manager =
            FailoverManager::new();

        manager
            .register(
                FailoverBackend::new(
                    "npcap",
                    1,
                )
                .unwrap(),
            )
            .unwrap();

        assert_eq!(
            manager.select(
                BackendCapability::Filtering
            ),
            Err(
                FailoverError::CapabilityUnavailable
            )
        );
    }

    #[test]
    fn unregister_removes_candidate() {
        let mut manager =
            FailoverManager::new();

        manager
            .register(
                FailoverBackend::new(
                    "npcap",
                    1,
                )
                .unwrap(),
            )
            .unwrap();

        manager.unregister("npcap").unwrap();

        assert!(manager.is_empty());
        assert_eq!(
            manager.active_backend(),
            None
        );
    }

    #[test]
    fn clear_removes_all_backends() {
        let mut manager =
            FailoverManager::new();

        manager
            .register(
                FailoverBackend::new(
                    "npcap",
                    1,
                )
                .unwrap(),
            )
            .unwrap();

        manager.clear();

        assert!(manager.is_empty());

        assert_eq!(
            manager.active_backend(),
            None
        );

        assert_eq!(
            manager.state(),
            FailoverState::Ready
        );
    }

    #[test]
    fn failed_coordinator_can_become_ready_after_registration() {
        let mut manager =
            FailoverManager::new();

        manager.mark_failed();

        assert_eq!(
            manager.state(),
            FailoverState::Failed
        );

        manager
            .register(
                FailoverBackend::new(
                    "npcap",
                    1,
                )
                .unwrap(),
            )
            .unwrap();

        assert_eq!(
            manager.state(),
            FailoverState::Ready
        );
    }

    #[test]
    fn disabled_coordinator_cannot_activate() {
        let mut manager =
            FailoverManager::new();

        let mut backend =
            FailoverBackend::new(
                "npcap",
                1,
            )
            .unwrap();

        backend.add_capability(
            BackendCapability::Capture
        );

        manager.register(backend).unwrap();
        manager.disable();

        assert_eq!(
            manager.activate_best(
                BackendCapability::Capture
            ),
            Err(
                FailoverError::InvalidState
            )
        );
    }

    #[test]
    fn capability_overlap_is_allowed() {
        let mut manager =
            FailoverManager::new();

        let mut wfp =
            FailoverBackend::new(
                "wfp",
                10,
            )
            .unwrap();

        wfp.add_capability(
            BackendCapability::Filtering
        );

        let mut windivert =
            FailoverBackend::new(
                "windivert",
                20,
            )
            .unwrap();

        windivert.add_capability(
            BackendCapability::Filtering
        );

        manager.register(wfp).unwrap();
        manager.register(windivert).unwrap();

        assert_eq!(
            manager.candidates(
                BackendCapability::Filtering
            )
            .len(),
            2
        );
    }

    #[test]
    fn names_are_deterministic() {
        let mut manager =
            FailoverManager::new();

        manager
            .register(
                FailoverBackend::new(
                    "z",
                    1,
                )
                .unwrap(),
            )
            .unwrap();

        manager
            .register(
                FailoverBackend::new(
                    "a",
                    2,
                )
                .unwrap(),
            )
            .unwrap();

        assert_eq!(
            manager.names(),
            vec![
                "a".to_string(),
                "z".to_string(),
            ]
        );
    }
}