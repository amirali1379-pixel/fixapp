use gateway_capability::GatewayCapability;
use network_core::policy::GatewayPolicy;

fn enabled_policy() -> GatewayPolicy {
    GatewayPolicy { enabled: true, ..GatewayPolicy::default() }
}

#[test]
fn gateway_is_host_policy_driven() {
    let gateway = GatewayCapability::new(enabled_policy());
    assert!(gateway.policy().enabled);
    assert!(!gateway.enabled());
}

#[test]
fn gateway_requires_explicit_start() {
    let mut gateway = GatewayCapability::new(enabled_policy());
    assert!(gateway.start().is_ok());
    assert!(gateway.enabled());
    assert!(gateway.is_ready());
}

#[test]
fn disabled_gateway_policy_cannot_start() {
    let mut gateway = GatewayCapability::default();
    assert!(gateway.start().is_err());
    assert!(!gateway.enabled());
}

#[test]
fn gateway_stop_resolves_runtime_state() {
    let mut gateway = GatewayCapability::new(enabled_policy());
    gateway.start().unwrap();
    gateway.stop().unwrap();
    assert!(!gateway.enabled());
}
