pub mod connection_state;
pub mod egress;
pub mod forwarding;
pub mod gateway_context;
pub mod ingress;
pub mod nat;
pub mod neighbor;
pub mod policy;
pub mod routing;
pub mod state;

pub use connection_state::{
    ConnectionEntry,
    ConnectionKey,
    ConnectionProtocol,
    ConnectionState,
    ConnectionStateError,
    ConnectionStateTable,
};

pub use egress::{
    EgressError,
    EgressPacket,
    EgressProcessor,
};

pub use forwarding::{
    ForwardingDecision,
    ForwardingEntry,
    ForwardingError,
    ForwardingTable,
};

pub use gateway_context::{
    GatewayCapabilities,
    GatewayContext,
    GatewayLimits,
};

pub use ingress::{
    IngressError,
    IngressPacket,
    IngressProcessor,
};

pub use nat::{
    NatEntry,
    NatError,
    NatLookupDirection,
    NatProtocol,
    NatTable,
    NatTuple,
};

pub use neighbor::{
    NeighborCache,
    NeighborEntry,
    NeighborKey,
    NeighborState,
};

pub use policy::{
    GatewayPolicyController,
    PolicyError,
    PolicyEvaluator,
};

pub use routing::{
    RoutingEntry,
    RoutingTable,
};

pub use state::{
    GatewayState,
    GatewayStateError,
    GatewayStateManager,
};

use network_core::policy::GatewayPolicy;

/// Runtime state owned by the Gateway capability.
///
/// These tables remain independent from administrative Gateway lifecycle
/// state so degradation/failover does not silently discard connection or
/// translation state.
#[derive(Debug)]
pub struct GatewayRuntime {
    pub connections: ConnectionStateTable,
    pub nat: NatTable,
    pub routing: RoutingTable,
    pub forwarding: ForwardingTable,
    pub neighbors: NeighborCache,
    pub ingress: IngressProcessor,
    pub egress: EgressProcessor,
}

impl GatewayRuntime {
    pub fn with_limits(limits: GatewayLimits) -> Self {
        Self {
            connections: ConnectionStateTable::new(limits.max_connections),
            nat: NatTable::new(limits.max_nat_entries),
            routing: RoutingTable::new(),
            forwarding: ForwardingTable::new(),
            neighbors: NeighborCache::new(limits.max_neighbors),
            ingress: IngressProcessor::new(),
            egress: EgressProcessor::new(),
        }
    }

    pub fn cleanup_expired(&mut self) -> (usize, usize, usize) {
        (
            self.connections.remove_expired(),
            self.nat.remove_expired(),
            self.neighbors.remove_expired(),
        )
    }

    pub fn clear_state(&mut self) {
        self.connections.clear();
        self.nat.clear();
        self.routing.clear();
        self.forwarding.clear();
        self.neighbors.clear();
    }
}

impl Default for GatewayRuntime {
    fn default() -> Self {
        Self::with_limits(GatewayLimits::default())
    }
}

#[derive(Debug)]
pub struct GatewayCapability {
    enabled: bool,
    context: GatewayContext,
    runtime: GatewayRuntime,
}

impl GatewayCapability {
    pub fn new(policy: GatewayPolicy) -> Self {
        let mut context = GatewayContext::new();
        context.set_policy(policy);
        let runtime = GatewayRuntime::with_limits(context.limits());

        Self {
            enabled: false,
            context,
            runtime,
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn context(&self) -> &GatewayContext {
        &self.context
    }

    pub fn context_mut(&mut self) -> &mut GatewayContext {
        &mut self.context
    }

    pub fn runtime(&self) -> &GatewayRuntime {
        &self.runtime
    }

    pub fn runtime_mut(&mut self) -> &mut GatewayRuntime {
        &mut self.runtime
    }

    pub fn policy(&self) -> &GatewayPolicy {
        self.context.policy()
    }

    pub fn start(&mut self) -> Result<(), GatewayCapabilityError> {
        if !self.context.can_start() {
            return Err(GatewayCapabilityError::NotReady);
        }

        self.context
            .mark_active()
            .map_err(|_| GatewayCapabilityError::InvalidState)?;

        self.enabled = true;
        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), GatewayCapabilityError> {
        self.enabled = false;

        self.context
            .reset()
            .map_err(|_| GatewayCapabilityError::InvalidState)?;

        Ok(())
    }

    pub fn degrade(&mut self) -> Result<(), GatewayCapabilityError> {
        if !self.enabled {
            return Err(GatewayCapabilityError::NotRunning);
        }

        self.context
            .mark_degraded()
            .map_err(|_| GatewayCapabilityError::InvalidState)
    }

    pub fn fail(&mut self) -> Result<(), GatewayCapabilityError> {
        self.enabled = false;

        self.context
            .mark_error()
            .map_err(|_| GatewayCapabilityError::InvalidState)
    }

    pub fn is_ready(&self) -> bool {
        self.enabled && self.context.can_forward()
    }
}

impl Default for GatewayCapability {
    fn default() -> Self {
        Self::new(GatewayPolicy::default())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayCapabilityError {
    NotReady,
    NotRunning,
    InvalidState,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_policy() -> GatewayPolicy {
        GatewayPolicy {
            enabled: true,
            ..GatewayPolicy::default()
        }
    }

    #[test]
    fn gateway_starts_when_policy_allows_it() {
        let mut gateway = GatewayCapability::new(enabled_policy());

        assert!(!gateway.enabled());
        assert!(gateway.start().is_ok());
        assert!(gateway.enabled());
        assert!(gateway.is_ready());
    }

    #[test]
    fn disabled_policy_does_not_start() {
        let mut gateway = GatewayCapability::default();

        assert_eq!(
            gateway.start(),
            Err(GatewayCapabilityError::NotReady)
        );
        assert!(!gateway.enabled());
    }

    #[test]
    fn gateway_stops_cleanly() {
        let mut gateway = GatewayCapability::new(enabled_policy());

        gateway.start().unwrap();
        gateway.stop().unwrap();
        assert!(!gateway.enabled());
    }

    #[test]
    fn gateway_cannot_degrade_when_stopped() {
        let mut gateway = GatewayCapability::new(enabled_policy());

        assert_eq!(
            gateway.degrade(),
            Err(GatewayCapabilityError::NotRunning)
        );
    }

    #[test]
    fn gateway_can_degrade_when_running() {
        let mut gateway = GatewayCapability::new(enabled_policy());

        gateway.start().unwrap();
        assert!(gateway.degrade().is_ok());
        assert!(!gateway.is_ready());
    }

    #[test]
    fn gateway_can_fail() {
        let mut gateway = GatewayCapability::new(enabled_policy());

        gateway.start().unwrap();
        gateway.fail().unwrap();
        assert!(!gateway.enabled());
    }

    #[test]
    fn policy_is_available_through_gateway() {
        let gateway = GatewayCapability::new(enabled_policy());
        assert!(gateway.policy().enabled);
    }

    #[test]
    fn context_is_available() {
        let gateway = GatewayCapability::new(enabled_policy());
        assert!(gateway.context().can_start());
    }

    #[test]
    fn runtime_is_initialized_from_context_limits() {
        let gateway = GatewayCapability::new(enabled_policy());

        assert_eq!(
            gateway.runtime().connections.max_entries(),
            gateway.context().limits().max_connections
        );
        assert_eq!(
            gateway.runtime().nat.max_entries(),
            gateway.context().limits().max_nat_entries
        );
        assert_eq!(
            gateway.runtime().neighbors.max_entries(),
            gateway.context().limits().max_neighbors
        );
    }

    #[test]
    fn degraded_state_preserves_runtime_state() {
        let mut gateway = GatewayCapability::new(enabled_policy());
        let key = ConnectionKey::new(
            "192.168.1.10".parse().unwrap(),
            50_000,
            "8.8.8.8".parse().unwrap(),
            443,
            ConnectionProtocol::Tcp,
        );

        gateway
            .runtime_mut()
            .connections
            .insert(ConnectionEntry::new(key.clone(), 60).unwrap())
            .unwrap();
        gateway.start().unwrap();
        gateway.degrade().unwrap();

        assert!(gateway.runtime().connections.lookup(&key).is_some());
    }
}