// crates/backend-manager/src/complementarity.rs

#![forbid(unsafe_code)]

//! Backend Complementarity.
//!
//! Per APPLICATION_ROADMAP section 0.8 and PROJECT_NATURE section 16,
//! backends are complementary, not competing. No single backend is the
//! single source of truth for any capability required by the Engine.
//!
//! This module exposes:
//!
//! - `CapabilityStatus`     — availability of a capability at runtime
//! - `CapabilityCoverage`   — full report for a capability
//! - `CapabilityFallbackMatrix` — the intended primary/fallback layout
//! - `select_with_fallback` — Engine-facing selection helper
//! - `capability_status`    — Engine-facing status helper
//!
//! Ownership boundaries:
//!
//! - `BackendManager` owns lifecycle, health, and registered backends.
//! - `CapabilityRegistry` owns declared capability metadata.
//! - `FailoverManager` owns failover ordering and preference.
//! - This module owns **coverage aggregation only**.
//!
//! This module does NOT:
//! - start, stop, or reconfigure native backends
//! - mutate backend lifecycle or health
//! - decide Host policy
//! - perform DROP / PASS / MODIFY / REINJECT
//! - perform routing, NAT, or Gateway policy
//! - fabricate capability availability
//!
//! ## Primary vs Fallback
//!
//! The matrix below is the Engine's **intended** primary/fallback layout.
//! It is a design document, not a runtime guarantee. At runtime the
//! Engine must:
//!
//! 1. Query registered backends via `BackendManager`.
//! 2. Query declared capabilities via `CapabilityRegistry`.
//! 3. Verify actual lifecycle and health.
//! 4. Report `CapabilityStatus::Lost` when no backend can provide the
//!    capability, rather than fabricating coverage.
//!
//! ## Engine-owned capabilities
//!
//! `Forwarding` and `NatState` are Engine-owned (see CORE_MODEL and
//! APPLICATION_ROADMAP sections 0.12, 0.14, 20, 22). No native packet
//! backend currently declares them, and this module must not assume
//! any backend will provide them. When the Engine itself owns the
//! capability, the matrix returns an empty primary list and the
//! runtime report will reflect whatever backend (if any) explicitly
//! declares the capability.

use crate::{
    BackendCapability,
    BackendHealth,
    BackendLifecycle,
    BackendManager,
};

/// Runtime availability of a capability.
///
/// `CapabilityStatus` describes coverage, not policy. A capability
/// marked `Available` does not mean the Engine is allowed to use it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityStatus {
    /// At least one primary backend is currently operational.
    Available,

    /// No primary backend is operational, but at least one fallback
    /// backend is currently operational.
    ///
    /// The Engine reports this state explicitly instead of pretending
    /// primary coverage still exists.
    Degraded,

    /// No registered backend declares the capability.
    ///
    /// This is a **declaration gap**, not a runtime failure. The Engine
    /// must not invent a policy to compensate.
    Unavailable,

    /// At least one backend declares the capability, but none is
    /// currently lifecycle-available and healthy.
    ///
    /// The Engine reports this state explicitly instead of silently
    /// proceeding.
    Lost,
}

impl CapabilityStatus {
    /// True when the capability can currently be executed.
    pub fn is_usable(self) -> bool {
        matches!(self, Self::Available | Self::Degraded)
    }

    /// True when the capability should be reported as degraded.
    pub fn is_degraded(self) -> bool {
        self == Self::Degraded
    }

    /// True when the capability is not usable at all.
    pub fn is_unavailable(self) -> bool {
        matches!(self, Self::Unavailable | Self::Lost)
    }
}

/// Full coverage report for one capability.
///
/// `primary` and `fallbacks` are **names of backends**, not backend
/// objects. They are populated from the runtime registry so the report
/// reflects what actually exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityCoverage {
    pub capability: BackendCapability,
    pub status: CapabilityStatus,

    /// Registered backend that the Engine considers primary for this
    /// capability and that is currently operational.
    pub active: Option<String>,

    /// Registered backends the Engine considers primary for this
    /// capability (whether or not they are currently operational).
    pub primary: Vec<String>,

    /// Registered backends the Engine considers fallback for this
    /// capability (whether or not they are currently operational).
    pub fallbacks: Vec<String>,
}

impl CapabilityCoverage {
    fn empty(capability: BackendCapability) -> Self {
        Self {
            capability,
            status: CapabilityStatus::Unavailable,
            active: None,
            primary: Vec::new(),
            fallbacks: Vec::new(),
        }
    }

    /// True when the capability can currently be executed.
    pub fn is_usable(&self) -> bool {
        self.status.is_usable()
    }

    /// True when the capability is running on a fallback only.
    pub fn is_degraded(&self) -> bool {
        self.status.is_degraded()
    }
}

/// Intended primary/fallback layout for every capability.
///
/// The matrix is intentionally read-only and const-friendly.
///
/// `primary()` returns the Engine's **intended** primary backends for a
/// capability, and `fallbacks()` returns the intended fallback backends.
///
/// An empty slice means: "The Engine does not designate a primary (or
/// fallback) backend for this capability." It does NOT mean the
/// capability is unavailable — a backend may still declare the
/// capability at runtime and be selected explicitly.
pub struct CapabilityFallbackMatrix;

impl CapabilityFallbackMatrix {
    /// Engine's intended primary backends for a capability.
    ///
    /// Names are backend identifiers used by `BackendDescriptor::name`.
    pub const fn primary(capability: BackendCapability) -> &'static [&'static str] {
        match capability {
            // Native packet capabilities
            BackendCapability::Capture => &["npcap"],
            BackendCapability::L2Capture => &["npcap"],
            BackendCapability::RawEthernet => &["npcap"],
            BackendCapability::AdapterEnumeration => &["npcap"],

            BackendCapability::Ipv4 => &["windivert"],
            BackendCapability::Ipv6 => &["windivert"],
            BackendCapability::Tcp => &["windivert"],
            BackendCapability::Udp => &["windivert"],
            BackendCapability::Icmp => &["windivert"],
            BackendCapability::IcmpV6 => &["windivert"],
            BackendCapability::NetworkLayer => &["windivert"],
            BackendCapability::AddressMetadata => &["windivert"],

            BackendCapability::Interception => &["windivert"],
            BackendCapability::Filtering => &["windivert"],
            BackendCapability::Inspection => &["windivert"],
            BackendCapability::Direction => &["windivert"],

            BackendCapability::Modification => &["windivert"],
            BackendCapability::Pass => &["windivert"],
            BackendCapability::Drop => &["windivert"],
            BackendCapability::Reinjection => &["windivert"],

            BackendCapability::QueueControl => &["windivert"],
            BackendCapability::HandleLifetime => &["windivert"],
            BackendCapability::ErrorReporting => &["windivert"],

            // WFP-native capabilities
            BackendCapability::WfpEngineAccess => &["wfp"],
            BackendCapability::WfpFilters => &["wfp"],
            BackendCapability::WfpLayers => &["wfp"],
            BackendCapability::WfpFlows => &["wfp"],

            // Windows network-state capabilities
            BackendCapability::InterfaceInfo => &["iphelper"],
            BackendCapability::RouteInfo => &["iphelper"],
            BackendCapability::NeighborInfo => &["iphelper"],
            BackendCapability::GatewayInfo => &["iphelper"],

            // Diagnostics
            BackendCapability::Diagnostics => &["etw"],
            BackendCapability::Telemetry => &["etw"],

            // Engine-owned capabilities
            //
            // The Engine owns these. No native packet backend is
            // designated as primary.
            BackendCapability::Forwarding => &[],
            BackendCapability::NatState => &[],
        }
    }

    /// Engine's intended fallback backends for a capability.
    pub const fn fallbacks(capability: BackendCapability) -> &'static [&'static str] {
        match capability {
            // Layer-2 fallback is IP-layer interception where possible.
            BackendCapability::Capture => &["windivert"],
            BackendCapability::L2Capture => &["windivert"],
            BackendCapability::RawEthernet => &["windivert"],

            // IP-layer fallbacks can use raw L2 where possible.
            BackendCapability::Ipv4 => &["npcap"],
            BackendCapability::Ipv6 => &["npcap"],
            BackendCapability::Tcp => &["npcap"],
            BackendCapability::Udp => &["npcap"],
            BackendCapability::Icmp => &["npcap"],
            BackendCapability::IcmpV6 => &["npcap"],

            // Filtering / PASS / DROP can fall back to WFP.
            BackendCapability::Filtering => &["wfp"],
            BackendCapability::Pass => &["wfp"],
            BackendCapability::Drop => &["wfp"],

            // ARP / Neighbor can fall back to raw L2 where available.
            BackendCapability::NeighborInfo => &["npcap"],

            // No fallback designated for these capabilities.
            _ => &[],
        }
    }

    /// Returns `true` when the Engine intends a fallback for the
    /// capability.
    pub const fn has_fallback(capability: BackendCapability) -> bool {
        !Self::fallbacks(capability).is_empty()
    }
}

/// Computes a runtime coverage report for one capability.
///
/// The report is derived from:
/// - backends that are actually registered with `BackendManager`
/// - the capability declared by each backend
/// - current lifecycle and health
///
/// The matrix is used only to classify a registered backend as
/// **primary** or **fallback**. A registered backend that declares the
/// capability but is not named in the matrix is treated as a fallback
/// for classification purposes.
pub fn select_with_fallback(
    manager: &BackendManager,
    capability: BackendCapability,
) -> CapabilityCoverage {
    let mut coverage = CapabilityCoverage::empty(capability);

    let primary_names = CapabilityFallbackMatrix::primary(capability);
    let fallback_names = CapabilityFallbackMatrix::fallbacks(capability);

    for name in manager.names() {
        let Ok(runtime) = manager.runtime_state(&name) else {
            continue;
        };

        if !runtime.supports(capability) {
            continue;
        }

        let is_declared_primary = primary_names.iter().any(|n| *n == name);
        let is_declared_fallback = fallback_names.iter().any(|n| *n == name);

        if is_declared_primary {
            coverage.primary.push(name.clone());
        } else if is_declared_fallback {
            coverage.fallbacks.push(name.clone());
        } else {
            // The backend declares the capability but the matrix does
            // not classify it. Treat it as a fallback to avoid
            // silently granting primary status the Engine has not
            // designated.
            coverage.fallbacks.push(name.clone());
        }
    }

    coverage.primary.sort();
    coverage.fallbacks.sort();

    let is_operational = |name: &str| -> bool {
        let Ok(runtime) = manager.runtime_state(name) else {
            return false;
        };

        let lifecycle_ok = matches!(
            runtime.lifecycle,
            BackendLifecycle::Running | BackendLifecycle::Degraded
        );

        if !lifecycle_ok {
            return false;
        }

        manager
            .health(name)
            .map(|h| h != BackendHealth::Unhealthy)
            .unwrap_or(false)
    };

    if let Some(active) = coverage
        .primary
        .iter()
        .find(|name| is_operational(name))
        .cloned()
    {
        coverage.active = Some(active);
        coverage.status = CapabilityStatus::Available;
        return coverage;
    }

    if let Some(active) = coverage
        .fallbacks
        .iter()
        .find(|name| is_operational(name))
        .cloned()
    {
        coverage.active = Some(active);
        coverage.status = CapabilityStatus::Degraded;
        return coverage;
    }

    if coverage.primary.is_empty() && coverage.fallbacks.is_empty() {
        coverage.status = CapabilityStatus::Unavailable;
    } else {
        coverage.status = CapabilityStatus::Lost;
    }

    coverage
}

/// Convenience wrapper for `select_with_fallback(...).status`.
pub fn capability_status(
    manager: &BackendManager,
    capability: BackendCapability,
) -> CapabilityStatus {
    select_with_fallback(manager, capability).status
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BackendDescriptor,
        BackendManager,
        CapabilitySet,
    };
    use packet_bus::PacketBus;
    use std::sync::Arc;

    fn descriptor(
        name: &str,
        capabilities: &[BackendCapability],
    ) -> BackendDescriptor {
        BackendDescriptor::new(
            name,
            "1.0.0",
            "complementarity test backend",
            CapabilitySet::from(capabilities.iter().copied()),
        )
    }

    fn running(manager: &BackendManager, name: &str) {
        let bus = Arc::new(PacketBus::new(100));
        manager.start(name, bus).unwrap();
        manager.mark_running(name).unwrap();
    }

    #[test]
    fn primary_backend_yields_available() {
        let manager = BackendManager::new();
        manager
            .register(descriptor("npcap", &[BackendCapability::Capture]))
            .unwrap();
        running(&manager, "npcap");

        let coverage =
            select_with_fallback(&manager, BackendCapability::Capture);

        assert_eq!(coverage.status, CapabilityStatus::Available);
        assert_eq!(coverage.active.as_deref(), Some("npcap"));
    }

    #[test]
    fn fallback_backend_yields_degraded() {
        let manager = BackendManager::new();
        manager
            .register(descriptor("windivert", &[BackendCapability::Capture]))
            .unwrap();
        running(&manager, "windivert");

        let coverage =
            select_with_fallback(&manager, BackendCapability::Capture);

        assert_eq!(coverage.status, CapabilityStatus::Degraded);
        assert_eq!(coverage.active.as_deref(), Some("windivert"));
    }

    #[test]
    fn missing_backend_yields_unavailable() {
        let manager = BackendManager::new();

        let coverage =
            select_with_fallback(&manager, BackendCapability::Capture);

        assert_eq!(coverage.status, CapabilityStatus::Unavailable);
        assert!(coverage.primary.is_empty());
        assert!(coverage.fallbacks.is_empty());
    }

    #[test]
    fn declared_but_not_running_yields_lost() {
        let manager = BackendManager::new();
        manager
            .register(descriptor("npcap", &[BackendCapability::Capture]))
            .unwrap();

        let coverage =
            select_with_fallback(&manager, BackendCapability::Capture);

        assert_eq!(coverage.status, CapabilityStatus::Lost);
    }

    #[test]
    fn engine_owned_capability_has_no_primary() {
        assert!(
            CapabilityFallbackMatrix::primary(BackendCapability::Forwarding)
                .is_empty()
        );
        assert!(
            CapabilityFallbackMatrix::primary(BackendCapability::NatState)
                .is_empty()
        );
    }

    #[test]
    fn matrix_fallback_rules_are_stable() {
        assert_eq!(
            CapabilityFallbackMatrix::primary(BackendCapability::Capture),
            &["npcap"]
        );
        assert_eq!(
            CapabilityFallbackMatrix::fallbacks(BackendCapability::Capture),
            &["windivert"]
        );
        assert_eq!(
            CapabilityFallbackMatrix::primary(BackendCapability::Filtering),
            &["windivert"]
        );
        assert_eq!(
            CapabilityFallbackMatrix::fallbacks(BackendCapability::Filtering),
            &["wfp"]
        );
        assert!(
            !CapabilityFallbackMatrix::has_fallback(
                BackendCapability::Modification
            )
        );
    }
}