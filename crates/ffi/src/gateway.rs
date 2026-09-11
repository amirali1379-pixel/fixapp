// Gateway control path — Host policy only.
use std::sync::atomic::Ordering;

use network_core::policy::GatewayPolicy;
use network_core::{EngineError, EngineErrorCode, EngineResult};
use backend_manager::BackendCapability;
use gateway_capability::{GatewayCapabilities, GatewayCapability};
use crate::engine::EngineRuntime;

impl EngineRuntime {
    pub fn gateway_config(&self, policy: GatewayPolicy) -> EngineResult<()> {
        self.require_running()?;

        policy.validate().map_err(|_| {
            EngineError::with_message(
                EngineErrorCode::InvalidArgument,
                "invalid gateway policy",
            )
        })?;

        let snapshot = self
            .network_state
            .lock()
            .map_err(|_| {
                EngineError::with_message(
                    EngineErrorCode::InternalError,
                    "network state mutex poisoned",
                )
            })?
            .snapshot();

        if let Some(nat) = &policy.nat {
            if nat.enabled {
                let interface_id = nat.external_interface_id.ok_or_else(|| {
                    EngineError::with_message(
                        EngineErrorCode::InvalidArgument,
                        "enabled NAT requires an external interface",
                    )
                })? as u64;

                if snapshot.find_interface(interface_id).is_none() {
                    return Err(EngineError::with_message(
                        EngineErrorCode::CapabilityUnavailable,
                        "NAT external interface is not present in NetworkState",
                    ));
                }
            }
        }

        if let Some(forwarding) = &policy.forwarding {
            if forwarding.enabled {
                let ingress = forwarding.ingress_interface_id.ok_or_else(|| {
                    EngineError::with_message(
                        EngineErrorCode::InvalidArgument,
                        "enabled forwarding requires an ingress interface",
                    )
                })? as u64;
                let egress = forwarding.egress_interface_id.ok_or_else(|| {
                    EngineError::with_message(
                        EngineErrorCode::InvalidArgument,
                        "enabled forwarding requires an egress interface",
                    )
                })? as u64;

                if snapshot.find_interface(ingress).is_none()
                    || snapshot.find_interface(egress).is_none()
                {
                    return Err(EngineError::with_message(
                        EngineErrorCode::CapabilityUnavailable,
                        "gateway forwarding interface is not present in NetworkState",
                    ));
                }
            }
        }

        if let Some(interface_id) = policy.routing.preferred_interface_id {
            if snapshot.find_interface(interface_id as u64).is_none() {
                return Err(EngineError::with_message(
                    EngineErrorCode::CapabilityUnavailable,
                    "preferred routing interface is not present in NetworkState",
                ));
            }
        }

        let forwarding_requested = policy
            .forwarding
            .as_ref()
            .is_some_and(|forwarding| forwarding.enabled);
        let nat_requested = policy
            .nat
            .as_ref()
            .is_some_and(|nat| nat.enabled);

        let reinjection_available = !self
            .backend_manager
            .find_capable(BackendCapability::Reinjection)
            .is_empty();
        let routing_available = !self
            .backend_manager
            .find_capable(BackendCapability::RouteInfo)
            .is_empty();
        let neighbor_available = !self
            .backend_manager
            .find_capable(BackendCapability::NeighborInfo)
            .is_empty();

        if forwarding_requested && !reinjection_available {
            return Err(EngineError::with_message(
                EngineErrorCode::CapabilityUnavailable,
                "no available backend supports reinjection; forwarding cannot be enabled",
            ));
        }

        if forwarding_requested && !routing_available {
            return Err(EngineError::with_message(
                EngineErrorCode::CapabilityUnavailable,
                "routing capability is unavailable from active backends",
            ));
        }

        if forwarding_requested && snapshot.routes.is_empty() {
            return Err(EngineError::with_message(
                EngineErrorCode::CapabilityUnavailable,
                "routing capability is unavailable: NetworkState contains no routes",
            ));
        }

        if forwarding_requested && !neighbor_available {
            return Err(EngineError::with_message(
                EngineErrorCode::CapabilityUnavailable,
                "neighbor capability is unavailable from active backends",
            ));
        }

        // The validated Host policy is the normalized runtime configuration.
        // Only capabilities actually available from Engine/backends are handed
        // to the Gateway; policy does not manufacture missing capabilities.
        let mut capability = GatewayCapability::new(policy);
        capability.context_mut().set_capabilities(GatewayCapabilities {
            forwarding: reinjection_available,
            routing: routing_available && !snapshot.routes.is_empty(),
            // NAT is an Engine capability represented by the gateway runtime;
            // the requested Host policy controls whether it is used.
            nat: nat_requested,
            neighbor_resolution: neighbor_available,
        });

        let mut gateway = self.gateway.lock().map_err(|_| {
            EngineError::with_message(
                EngineErrorCode::InternalError,
                "gateway mutex poisoned",
            )
        })?;
        *gateway = capability;
        Ok(())
    }

    pub fn gateway_start(&self) -> EngineResult<()> {
        self.require_running()?;
        {
            let gateway = self.gateway.lock().map_err(|_| EngineError::with_message(EngineErrorCode::InternalError, "gateway mutex poisoned"))?;
            gateway.policy().validate().map_err(|_| EngineError::with_message(EngineErrorCode::InvalidArgument, "stored gateway policy is invalid"))?;
            let capabilities = gateway.context().capabilities();
            if gateway.policy().forwarding.as_ref().is_some_and(|p| p.enabled) {
                if !capabilities.forwarding {
                    return Err(EngineError::with_message(EngineErrorCode::CapabilityUnavailable, "gateway forwarding capability is unavailable"));
                }
                if !capabilities.routing {
                    return Err(EngineError::with_message(EngineErrorCode::CapabilityUnavailable, "gateway routing capability is unavailable"));
                }
                if !capabilities.neighbor_resolution {
                    return Err(EngineError::with_message(EngineErrorCode::CapabilityUnavailable, "gateway neighbor capability is unavailable"));
                }
            }
            if gateway.policy().nat.as_ref().is_some_and(|p| p.enabled)
                && !capabilities.nat
            {
                return Err(EngineError::with_message(EngineErrorCode::CapabilityUnavailable, "gateway NAT capability is unavailable"));
            }
        }
        let mut gateway = self.gateway.lock().map_err(|_| EngineError::with_message(EngineErrorCode::InternalError, "gateway mutex poisoned"))?;
        gateway.start().map_err(|_| EngineError::with_message(EngineErrorCode::GatewayNotReady, "failed to start gateway"))?;
        Ok(())
    }

    pub fn gateway_stop(&self) -> EngineResult<()> {
        self.require_running()?;
        let mut gateway = self.gateway.lock().map_err(|_| EngineError::with_message(EngineErrorCode::InternalError, "gateway mutex poisoned"))?;
        if !gateway.enabled() { return Ok(()); }
        gateway.stop().map_err(|_| EngineError::with_message(EngineErrorCode::GatewayNotReady, "failed to stop gateway"))?;
        self.statistics.gateway_packets_forwarded.fetch_add(0, Ordering::Relaxed);
        Ok(())
    }

    pub fn gateway_is_running(&self) -> bool {
        match self.gateway.lock() { Ok(gateway) => gateway.is_ready(), Err(_) => false }
    }
}
