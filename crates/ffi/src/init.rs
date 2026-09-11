// Engine initialization.
use backend_manager::BackendCapability;
use backend_iphelper::{IpHelperBackend, RouteProtocol as IpRouteProtocol, RouteType as IpRouteType, NeighborState as IpNeighborState, InterfaceType as IpInterfaceType, InterfaceOperationalState as IpInterfaceState};
use network_core::{EngineError, EngineErrorCode, EngineResult};
use network_state::{AddressInfo, GatewayInfo, GatewayType, InterfaceInfo, InterfaceKind, InterfaceState, NeighborInfo, NeighborState, RouteInfo, RouteProtocol, RouteType};
use crate::engine::EngineRuntime;

#[derive(Debug, Clone, Copy)]
pub struct EngineConfig { pub queue_capacity: usize, pub pool_max_size: usize, pub buffer_capacity: usize, pub max_flows: usize }
impl Default for EngineConfig { fn default() -> Self { Self { queue_capacity: 4096, pool_max_size: 1024, buffer_capacity: 65536, max_flows: 65_536 } } }
impl EngineConfig {
    pub fn validate(&self) -> EngineResult<()> {
        if self.queue_capacity == 0 { return Err(EngineError::with_message(EngineErrorCode::InvalidArgument, "queue_capacity must be greater than zero")); }
        if self.pool_max_size == 0 { return Err(EngineError::with_message(EngineErrorCode::InvalidArgument, "pool_max_size must be greater than zero")); }
        if self.buffer_capacity == 0 { return Err(EngineError::with_message(EngineErrorCode::InvalidArgument, "buffer_capacity must be greater than zero")); }
        if self.max_flows == 0 { return Err(EngineError::with_message(EngineErrorCode::InvalidArgument, "max_flows must be greater than zero")); }
        Ok(())
    }
}

fn synchronize_network_state(engine: &EngineRuntime, iphelper: &IpHelperBackend) -> EngineResult<()> {
    let interfaces = iphelper.interface_table().map_err(|_| EngineError::with_message(EngineErrorCode::BackendInitFailed, "IP Helper interface query failed"))?;
    let mut state_interfaces = Vec::with_capacity(interfaces.len());
    let mut addresses = Vec::new();

    for source in interfaces.all() {
        let kind = match source.interface_type {
            IpInterfaceType::Ethernet => InterfaceKind::Ethernet,
            IpInterfaceType::Wifi => InterfaceKind::Wifi,
            IpInterfaceType::Loopback => InterfaceKind::Loopback,
            IpInterfaceType::Tunnel => InterfaceKind::Tunnel,
            IpInterfaceType::Unknown => InterfaceKind::Unknown,
        };
        let state = match source.operational_state {
            IpInterfaceState::Up => InterfaceState::Up,
            IpInterfaceState::Down => InterfaceState::Down,
            IpInterfaceState::Testing => InterfaceState::Testing,
            IpInterfaceState::Unknown => InterfaceState::Unknown,
        };
        let mut info = InterfaceInfo::new(source.index as u64, source.name.clone())
            .with_description(source.description.clone())
            .with_kind(kind)
            .with_state(state)
            .with_if_index(source.index);
        if let Some(mac) = source.mac_address {
            info = info.with_mac(mac);
        }
        if source.mtu != 0 {
            if let Some(value) = info.clone().with_mtu(source.mtu) {
                info = value;
            }
        }
        for address in &source.addresses {
            if let Some(value) = AddressInfo::new(source.index as u64, address.address, address.prefix_length) {
                addresses.push(value);
            }
        }
        state_interfaces.push(info);
    }
    drop(interfaces);

    let routes = iphelper.route_table().map_err(|_| EngineError::with_message(EngineErrorCode::BackendInitFailed, "IP Helper route query failed"))?;
    let mut state_routes = Vec::with_capacity(routes.len());
    let mut gateways = Vec::new();
    for (id, source) in routes.all().iter().enumerate() {
        let protocol = match source.protocol {
            IpRouteProtocol::Local => RouteProtocol::Local,
            IpRouteProtocol::NetMgmt => RouteProtocol::NetMgmt,
            IpRouteProtocol::Other => RouteProtocol::Other,
            IpRouteProtocol::Icmp => RouteProtocol::Other,
            IpRouteProtocol::Unknown(_) => RouteProtocol::Unknown,
            _ => RouteProtocol::Other,
        };
        let route_type = match source.route_type {
            IpRouteType::Direct | IpRouteType::Indirect => RouteType::Unicast,
            IpRouteType::Invalid => RouteType::Unreachable,
            IpRouteType::Other => RouteType::Unknown,
        };
        if let Some(mut route) = RouteInfo::new(id as u64 + 1, source.destination, source.prefix_length, source.interface_index as u64) {
            if let Some(gateway) = source.next_hop { route = route.with_gateway(gateway).ok_or_else(|| EngineError::with_message(EngineErrorCode::BackendInitFailed, "IP Helper route gateway family mismatch"))?; }
            route = route.with_metric(source.metric).with_protocol(protocol).with_route_type(route_type);
            if source.prefix_length == 0 {
                if let Some(gateway) = source.next_hop {
                    let gateway_type = match source.protocol {
                        IpRouteProtocol::Local => GatewayType::OnLink,
                        IpRouteProtocol::NetMgmt => GatewayType::Static,
                        IpRouteProtocol::Other => GatewayType::Default,
                        IpRouteProtocol::Icmp => GatewayType::Default,
                        IpRouteProtocol::Unknown(_) => GatewayType::Unknown,
                        _ => GatewayType::Unknown,
                    };
                    gateways.push(GatewayInfo::new(source.interface_index as u64, gateway).with_type(gateway_type).with_metric(source.metric).with_reachable(true));
                }
            }
            state_routes.push(route);
        }
    }
    drop(routes);

    let neighbors = iphelper.neighbor_table().map_err(|_| EngineError::with_message(EngineErrorCode::BackendInitFailed, "IP Helper neighbor query failed"))?;
    let mut state_neighbors = Vec::with_capacity(neighbors.len());
    for source in neighbors.all() {
        let state = match source.state {
            IpNeighborState::Reachable => NeighborState::Reachable,
            IpNeighborState::Stale => NeighborState::Stale,
            IpNeighborState::Permanent => NeighborState::Permanent,
            IpNeighborState::Probe => NeighborState::Probe,
            IpNeighborState::Delay => NeighborState::Delay,
            IpNeighborState::Incomplete => NeighborState::Incomplete,
            IpNeighborState::Unreachable => NeighborState::Unreachable,
            IpNeighborState::Unknown => NeighborState::Unknown,
        };
        let mut info = NeighborInfo::new(source.key.interface_index as u64, source.key.address)
            .with_state(state);
        if let Some(mac) = source.mac_address { info = info.with_mac(mac); }
        state_neighbors.push(info);
    }
    drop(neighbors);

    let state = engine.network_state.lock().map_err(|_| EngineError::with_message(EngineErrorCode::InternalError, "network state mutex poisoned"))?;
    state.set_interfaces(state_interfaces);
    state.set_addresses(addresses);
    state.set_routes(state_routes);
    state.set_neighbors(state_neighbors);
    state.set_gateways(gateways);
    Ok(())
}

impl EngineRuntime {
    pub fn initialize(config: &EngineConfig) -> EngineResult<Self> {
        config.validate()?;
        let mut engine = EngineRuntime::new(config.queue_capacity, config.pool_max_size, config.buffer_capacity, config.max_flows);
        if engine.packet_bus.capacity() == 0 { return Err(EngineError::with_message(EngineErrorCode::InvalidArgument, "packet bus capacity must be greater than zero")); }

        engine.state.init()?;
        engine.mark_initialized();
        if let Err(error) = crate::backend_defaults::register_builtin_backends(&engine) { engine.mark_uninitialized(); return Err(error); }

        let mut iphelper = IpHelperBackend::new();
        if let Err(error) = iphelper.start() {
            engine.mark_uninitialized();
            return Err(EngineError::with_message(EngineErrorCode::BackendInitFailed, format!("IP Helper initialization failed: {:?}", error)));
        }
        if let Err(error) = synchronize_network_state(&engine, &iphelper) {
            let _ = iphelper.stop();
            engine.mark_uninitialized();
            return Err(error);
        }

        // The borrow ends before mark_uninitialized is called.
        let iphelper_stored = match engine.iphelper_backend.lock() {
            Ok(mut slot) => {
                *slot = Some(iphelper);
                true
            }
            Err(_) => false,
        };
        if !iphelper_stored {
            engine.mark_uninitialized();
            return Err(EngineError::with_message(EngineErrorCode::InternalError, "IP Helper backend mutex poisoned during initialization"));
        }

        let capture = engine.backend_manager.descriptors().into_iter()
            .find(|descriptor| descriptor.capabilities.contains(BackendCapability::Capture))
            .map(|descriptor| descriptor.name)
            .ok_or_else(|| EngineError::with_message(EngineErrorCode::CapabilityUnavailable, "no capture-capable backend is registered"))?;
        engine.set_active_capture_backend(Some(capture))?;

        let reinjection = engine.backend_manager.descriptors().into_iter()
            .find(|descriptor| descriptor.capabilities.contains(BackendCapability::Reinjection))
            .map(|descriptor| descriptor.name);
        if let Some(route) = reinjection { engine.set_active_reinjection_backend(Some(route))?; }

        let workers_started = match engine.metadata_workers.lock() {
            Ok(workers) => {
                workers.start_all();
                true
            }
            Err(_) => false,
        };
        if !workers_started {
            engine.mark_uninitialized();
            return Err(EngineError::with_message(EngineErrorCode::InternalError, "metadata worker pool mutex poisoned during initialization"));
        }
        Ok(engine)
    }
}