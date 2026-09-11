pub use network_core::policy::GatewayPolicy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    InvalidPolicy,
}

#[derive(Debug, Clone)]
pub struct GatewayPolicyController {
    policy: GatewayPolicy,
}

impl GatewayPolicyController {
    pub fn new(policy: GatewayPolicy) -> Result<Self, PolicyError> {
        Self::validate(&policy)?;

        Ok(Self { policy })
    }

    pub fn policy(&self) -> &GatewayPolicy {
        &self.policy
    }

    pub fn policy_mut(&mut self) -> &mut GatewayPolicy {
        &mut self.policy
    }

    pub fn replace(
        &mut self,
        policy: GatewayPolicy,
    ) -> Result<(), PolicyError> {
        Self::validate(&policy)?;
        self.policy = policy;
        Ok(())
    }

    pub fn is_enabled(&self) -> bool {
        self.policy.enabled
    }

    pub fn enable(&mut self) {
        self.policy.enabled = true;
    }

    pub fn disable(&mut self) {
        self.policy.enabled = false;
    }

    fn validate(
        policy: &GatewayPolicy,
    ) -> Result<(), PolicyError> {
        // Policy is Host-owned.
        //
        // This layer validates the policy object itself but does not
        // invent routing, NAT, forwarding, or security decisions.
        //
        // Additional policy fields can be validated here as the
        // network-core contract evolves.

        if !policy.enabled {
            return Ok(());
        }

        Ok(())
    }
}

impl Default for GatewayPolicyController {
    fn default() -> Self {
        Self {
            policy: GatewayPolicy::default(),
        }
    }
}

#[derive(Debug, Default)]
pub struct PolicyEvaluator;

impl PolicyEvaluator {
    pub fn new() -> Self {
        Self
    }

    pub fn allows_gateway(
        &self,
        policy: &GatewayPolicy,
    ) -> bool {
        policy.enabled
    }

    pub fn validate(
        &self,
        policy: &GatewayPolicy,
    ) -> Result<(), PolicyError> {
        GatewayPolicyController::validate(policy)
    }
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

    fn disabled_policy() -> GatewayPolicy {
        GatewayPolicy {
            enabled: false,
            ..GatewayPolicy::default()
        }
    }

    #[test]
    fn enabled_policy_is_accepted() {
        let controller =
            GatewayPolicyController::new(
                enabled_policy(),
            );

        assert!(controller.is_ok());

        assert!(
            controller
                .unwrap()
                .is_enabled()
        );
    }

    #[test]
    fn disabled_policy_is_accepted() {
        let controller =
            GatewayPolicyController::new(
                disabled_policy(),
            )
            .unwrap();

        assert!(!controller.is_enabled());
    }

    #[test]
    fn policy_can_be_enabled() {
        let mut controller =
            GatewayPolicyController::default();

        assert!(!controller.is_enabled());

        controller.enable();

        assert!(controller.is_enabled());
    }

    #[test]
    fn policy_can_be_disabled() {
        let mut controller =
            GatewayPolicyController::new(
                enabled_policy(),
            )
            .unwrap();

        controller.disable();

        assert!(!controller.is_enabled());
    }

    #[test]
    fn policy_can_be_replaced() {
        let mut controller =
            GatewayPolicyController::default();

        controller
            .replace(enabled_policy())
            .unwrap();

        assert!(controller.is_enabled());

        controller
            .replace(disabled_policy())
            .unwrap();

        assert!(!controller.is_enabled());
    }

    #[test]
    fn evaluator_uses_host_policy() {
        let evaluator =
            PolicyEvaluator::new();

        assert!(
            evaluator.allows_gateway(
                &enabled_policy()
            )
        );

        assert!(
            !evaluator.allows_gateway(
                &disabled_policy()
            )
        );
    }

    #[test]
    fn evaluator_validates_policy() {
        let evaluator =
            PolicyEvaluator::new();

        assert!(
            evaluator
                .validate(
                    &enabled_policy()
                )
                .is_ok()
        );

        assert!(
            evaluator
                .validate(
                    &disabled_policy()
                )
                .is_ok()
        );
    }
}