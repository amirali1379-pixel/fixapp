use crate::error::EngineError;
use crate::Direction;

/// Host policy decision.
///
/// These structures represent Host intent only.
/// No policy generation or execution is performed here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny,
}

impl Default for PolicyDecision {
    fn default() -> Self {
        Self::Allow
    }
}

/// NAT policy mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatPolicyMode {
    Disabled,
    SourceNat,
    DestinationNat,
    Masquerade,
}

impl Default for NatPolicyMode {
    fn default() -> Self {
        Self::Disabled
    }
}

/// Host NAT policy configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatPolicy {
    pub enabled: bool,
    pub mode: NatPolicyMode,
    pub external_interface_id: Option<u32>,
}

impl Default for NatPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: NatPolicyMode::Disabled,
            external_interface_id: None,
        }
    }
}

impl NatPolicy {
    pub fn validate(&self) -> Result<(), EngineError> {
        if !self.enabled {
            if self.mode != NatPolicyMode::Disabled {
                return Err(EngineError::configuration_invalid());
            }
            return Ok(());
        }

        if self.mode == NatPolicyMode::Disabled {
            return Err(EngineError::configuration_invalid());
        }

        match self.mode {
            NatPolicyMode::SourceNat
            | NatPolicyMode::DestinationNat
            | NatPolicyMode::Masquerade => {
                if self.external_interface_id.is_none() {
                    return Err(EngineError::configuration_invalid());
                }
            }
            NatPolicyMode::Disabled => {}
        }

        Ok(())
    }
}

/// Host forwarding policy configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardingPolicy {
    pub enabled: bool,
    pub ingress_interface_id: Option<u32>,
    pub egress_interface_id: Option<u32>,
    pub decision: PolicyDecision,
}

impl Default for ForwardingPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            ingress_interface_id: None,
            egress_interface_id: None,
            decision: PolicyDecision::Allow,
        }
    }
}

impl ForwardingPolicy {
    pub fn validate(&self) -> Result<(), EngineError> {
        if !self.enabled {
            return Ok(());
        }

        if self.ingress_interface_id.is_none()
            || self.egress_interface_id.is_none()
        {
            return Err(EngineError::configuration_invalid());
        }

        if self.ingress_interface_id == self.egress_interface_id {
            return Err(EngineError::configuration_invalid());
        }

        Ok(())
    }
}

/// Routing context for gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingContext {
    pub table_id: u32,
    pub preferred_interface_id: Option<u32>,
}

impl Default for RoutingContext {
    fn default() -> Self {
        Self {
            table_id: 0,
            preferred_interface_id: None,
        }
    }
}

impl RoutingContext {
    pub fn validate(&self) -> Result<(), EngineError> {
        Ok(())
    }
}

/// Host Gateway policy configuration.
///
/// This represents Host intent only. The Engine validates and
/// applies this policy but does not generate policy autonomously.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayPolicy {
    pub enabled: bool,
    pub default_decision: PolicyDecision,
    pub nat: Option<NatPolicy>,
    pub forwarding: Option<ForwardingPolicy>,
    pub routing: RoutingContext,
}

impl Default for GatewayPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            default_decision: PolicyDecision::Deny,
            nat: None,
            forwarding: None,
            routing: RoutingContext::default(),
        }
    }
}

impl GatewayPolicy {
    pub fn validate(&self) -> Result<(), EngineError> {
        if let Some(nat) = &self.nat {
            nat.validate()?;
        }

        if let Some(forwarding) = &self.forwarding {
            forwarding.validate()?;
        }

        self.routing.validate()?;

        if !self.enabled {
            return Ok(());
        }

        if self.forwarding.is_none() {
            return Err(EngineError::configuration_invalid());
        }

        Ok(())
    }

    pub const fn allows_default(&self) -> bool {
        matches!(self.default_decision, PolicyDecision::Allow)
    }

    pub const fn denies_default(&self) -> bool {
        matches!(self.default_decision, PolicyDecision::Deny)
    }
}

/// Host filter policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterPolicy {
    pub enabled: bool,
    pub rules: Vec<FilterRule>,
}

impl Default for FilterPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            rules: Vec::new(),
        }
    }
}

/// Individual filter rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterRule {
    pub priority: u32,
    pub match_direction: Option<Direction>,
    pub match_protocol: Option<crate::Protocol>,
    pub match_src_ip: Option<std::net::IpAddr>,
    pub match_dst_ip: Option<std::net::IpAddr>,
    pub match_src_port: Option<u16>,
    pub match_dst_port: Option<u16>,
    pub action: PacketActionPolicy,
}

/// Packet action policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketActionPolicy {
    Pass,
    Drop,
    Inspect,
}

/// Host packet action policy configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketActionPolicyConfig {
    pub default_action: PacketActionPolicy,
    pub rules: Vec<FilterRule>,
}

/// Host routing policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingPolicy {
    pub enabled: bool,
    pub routes: Vec<StaticRoute>,
}

/// Static route entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticRoute {
    pub destination: std::net::IpAddr,
    pub prefix_len: u8,
    pub next_hop: Option<std::net::IpAddr>,
    pub interface_id: Option<u32>,
    pub metric: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_is_disabled() {
        let policy = GatewayPolicy::default();
        assert!(!policy.enabled);
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn enabled_gateway_requires_forwarding() {
        let policy = GatewayPolicy {
            enabled: true,
            ..GatewayPolicy::default()
        };
        assert!(policy.validate().is_err());
    }

    #[test]
    fn valid_forwarding_policy() {
        let policy = ForwardingPolicy {
            enabled: true,
            ingress_interface_id: Some(1),
            egress_interface_id: Some(2),
            decision: PolicyDecision::Allow,
        };
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn same_ingress_and_egress_is_invalid() {
        let policy = ForwardingPolicy {
            enabled: true,
            ingress_interface_id: Some(1),
            egress_interface_id: Some(1),
            decision: PolicyDecision::Allow,
        };
        assert!(policy.validate().is_err());
    }

    #[test]
    fn enabled_nat_requires_mode() {
        let policy = NatPolicy {
            enabled: true,
            mode: NatPolicyMode::Disabled,
            external_interface_id: Some(2),
        };
        assert!(policy.validate().is_err());
    }

    #[test]
    fn valid_masquerade_policy() {
        let policy = NatPolicy {
            enabled: true,
            mode: NatPolicyMode::Masquerade,
            external_interface_id: Some(2),
        };
        assert!(policy.validate().is_ok());
    }
}
