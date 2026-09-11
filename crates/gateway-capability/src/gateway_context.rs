use crate::policy::GatewayPolicy;
use crate::state::{GatewayState, GatewayStateManager};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayLimits {
    pub max_connections: usize,
    pub max_nat_entries: usize,
    pub max_neighbors: usize,
    pub max_routes: usize,
    pub max_forwarding_entries: usize,
}

impl GatewayLimits {
    pub fn new(
        max_connections: usize,
        max_nat_entries: usize,
        max_neighbors: usize,
        max_routes: usize,
        max_forwarding_entries: usize,
    ) -> Self {
        Self {
            max_connections,
            max_nat_entries,
            max_neighbors,
            max_routes,
            max_forwarding_entries,
        }
    }
}

impl Default for GatewayLimits {
    fn default() -> Self {
        Self {
            max_connections: 65_536,
            max_nat_entries: 65_536,
            max_neighbors: 65_536,
            max_routes: 16_384,
            max_forwarding_entries: 16_384,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayCapabilities {
    pub forwarding: bool,
    pub routing: bool,
    pub nat: bool,
    pub neighbor_resolution: bool,
}

impl GatewayCapabilities {
    pub fn none() -> Self {
        Self {
            forwarding: false,
            routing: false,
            nat: false,
            neighbor_resolution: false,
        }
    }

    pub fn all() -> Self {
        Self {
            forwarding: true,
            routing: true,
            nat: true,
            neighbor_resolution: true,
        }
    }

    pub fn forwarding_ready(self) -> bool {
        self.forwarding
            && self.routing
            && self.neighbor_resolution
    }

    pub fn nat_ready(self) -> bool {
        self.forwarding_ready() && self.nat
    }
}

impl Default for GatewayCapabilities {
    fn default() -> Self {
        Self::none()
    }
}

#[derive(Debug)]
pub struct GatewayContext {
    policy: GatewayPolicy,
    limits: GatewayLimits,
    capabilities: GatewayCapabilities,
    state: GatewayStateManager,
}

impl GatewayContext {
    pub fn new() -> Self {
        Self {
            policy: GatewayPolicy::default(),
            limits: GatewayLimits::default(),
            capabilities: GatewayCapabilities::none(),
            state: GatewayStateManager::new(),
        }
    }

    pub fn with_limits(limits: GatewayLimits) -> Self {
        Self {
            policy: GatewayPolicy::default(),
            limits,
            capabilities: GatewayCapabilities::none(),
            state: GatewayStateManager::new(),
        }
    }

    pub fn policy(&self) -> &GatewayPolicy {
        &self.policy
    }

    pub fn policy_mut(&mut self) -> &mut GatewayPolicy {
        &mut self.policy
    }

    pub fn set_policy(&mut self, policy: GatewayPolicy) {
        self.policy = policy;
    }

    pub fn limits(&self) -> GatewayLimits {
        self.limits
    }

    pub fn set_limits(&mut self, limits: GatewayLimits) {
        self.limits = limits;
    }

    pub fn capabilities(&self) -> GatewayCapabilities {
        self.capabilities
    }

    pub fn set_capabilities(
        &mut self,
        capabilities: GatewayCapabilities,
    ) {
        self.capabilities = capabilities;
    }

    pub fn state(&self) -> GatewayState {
        self.state.current()
    }

    pub fn state_manager(&self) -> &GatewayStateManager {
        &self.state
    }

    pub fn state_manager_mut(
        &mut self,
    ) -> &mut GatewayStateManager {
        &mut self.state
    }

    pub fn can_start(&self) -> bool {
        self.policy.enabled
            && self.capabilities.forwarding_ready()
            && matches!(
                self.state(),
                GatewayState::Idle
                    | GatewayState::Degraded
            )
    }

    pub fn can_forward(&self) -> bool {
        self.policy.enabled
            && self.capabilities.forwarding_ready()
            && matches!(
                self.state(),
                GatewayState::Active
                    | GatewayState::Degraded
            )
    }

    pub fn can_nat(&self) -> bool {
        self.can_forward()
            && self.capabilities.nat
    }

    pub fn mark_active(
        &mut self,
    ) -> Result<(), crate::state::GatewayStateError> {
        self.state.activate()
    }

    pub fn mark_degraded(
        &mut self,
    ) -> Result<(), crate::state::GatewayStateError> {
        self.state.degrade()
    }

    pub fn mark_error(
        &mut self,
    ) -> Result<(), crate::state::GatewayStateError> {
        self.state.fail()
    }

    pub fn reset(
        &mut self,
    ) -> Result<(), crate::state::GatewayStateError> {
        self.state.reset()
    }
}

impl Default for GatewayContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_context_is_disabled() {
        let context = GatewayContext::new();

        assert!(!context.policy().enabled);
        assert_eq!(
            context.state(),
            GatewayState::Idle
        );
        assert!(!context.can_start());
        assert!(!context.can_forward());
        assert!(!context.can_nat());
    }

    #[test]
    fn all_capabilities_enable_forwarding_readiness() {
        let mut context = GatewayContext::new();

        context.policy_mut().enabled = true;
        context.set_capabilities(
            GatewayCapabilities::all()
        );

        assert!(context.can_start());
    }

    #[test]
    fn forwarding_requires_policy() {
        let mut context = GatewayContext::new();

        context.set_capabilities(
            GatewayCapabilities::all()
        );

        assert!(!context.can_start());

        context.policy_mut().enabled = true;

        assert!(context.can_start());
    }

    #[test]
    fn forwarding_requires_routing() {
        let mut context = GatewayContext::new();

        context.policy_mut().enabled = true;

        context.set_capabilities(
            GatewayCapabilities {
                forwarding: true,
                routing: false,
                nat: true,
                neighbor_resolution: true,
            },
        );

        assert!(!context.can_start());
    }

    #[test]
    fn forwarding_requires_neighbor_resolution() {
        let mut context = GatewayContext::new();

        context.policy_mut().enabled = true;

        context.set_capabilities(
            GatewayCapabilities {
                forwarding: true,
                routing: true,
                nat: true,
                neighbor_resolution: false,
            },
        );

        assert!(!context.can_start());
    }

    #[test]
    fn active_context_can_forward() {
        let mut context = GatewayContext::new();

        context.policy_mut().enabled = true;
        context.set_capabilities(
            GatewayCapabilities::all()
        );

        context.mark_active().unwrap();

        assert!(context.can_forward());
        assert!(context.can_nat());
    }

    #[test]
    fn nat_requires_nat_capability() {
        let mut context = GatewayContext::new();

        context.policy_mut().enabled = true;

        context.set_capabilities(
            GatewayCapabilities {
                forwarding: true,
                routing: true,
                nat: false,
                neighbor_resolution: true,
            },
        );

        context.mark_active().unwrap();

        assert!(context.can_forward());
        assert!(!context.can_nat());
    }

    #[test]
    fn degraded_state_can_still_forward() {
        let mut context = GatewayContext::new();

        context.policy_mut().enabled = true;
        context.set_capabilities(
            GatewayCapabilities::all()
        );

        context.mark_active().unwrap();
        context.mark_degraded().unwrap();

        assert!(context.can_forward());
        assert!(context.can_nat());
    }

    #[test]
    fn limits_are_configurable() {
        let limits = GatewayLimits::new(
            100,
            200,
            300,
            400,
            500,
        );

        let context =
            GatewayContext::with_limits(limits);

        assert_eq!(
            context.limits().max_connections,
            100
        );
        assert_eq!(
            context.limits().max_nat_entries,
            200
        );
        assert_eq!(
            context.limits().max_neighbors,
            300
        );
        assert_eq!(
            context.limits().max_routes,
            400
        );
        assert_eq!(
            context
                .limits()
                .max_forwarding_entries,
            500
        );
    }

    #[test]
    fn reset_returns_to_idle() {
        let mut context = GatewayContext::new();

        context.policy_mut().enabled = true;
        context.set_capabilities(
            GatewayCapabilities::all()
        );

        context.mark_active().unwrap();
        context.reset().unwrap();

        assert_eq!(
            context.state(),
            GatewayState::Idle
        );
        assert!(!context.can_forward());
    }
}