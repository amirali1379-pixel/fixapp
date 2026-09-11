#![forbid(unsafe_code)]

use crate::{
    AddressInfo,
    GatewayInfo,
    InterfaceInfo,
    NeighborInfo,
    RouteInfo,
};

use std::sync::RwLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsConfiguration {
    pub servers: Vec<std::net::IpAddr>,
    pub search_domains: Vec<String>,
    pub enabled: bool,
}

impl Default for DnsConfiguration {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            search_domains: Vec::new(),
            enabled: true,
        }
    }
}

impl DnsConfiguration {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_configured(&self) -> bool {
        self.enabled && !self.servers.is_empty()
    }

    pub fn add_server(
        &mut self,
        server: std::net::IpAddr,
    ) {
        if !self.servers.contains(&server) {
            self.servers.push(server);
        }
    }

    pub fn remove_server(
        &mut self,
        server: std::net::IpAddr,
    ) -> bool {
        if let Some(index) =
            self.servers.iter().position(|x| *x == server)
        {
            self.servers.remove(index);
            true
        } else {
            false
        }
    }

    pub fn clear(&mut self) {
        self.servers.clear();
        self.search_domains.clear();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkStateSnapshot {
    pub interfaces: Vec<InterfaceInfo>,
    pub addresses: Vec<AddressInfo>,
    pub routes: Vec<RouteInfo>,
    pub neighbors: Vec<NeighborInfo>,
    pub gateways: Vec<GatewayInfo>,
    pub dns: DnsConfiguration,
    pub generation: u64,
}

impl Default for NetworkStateSnapshot {
    fn default() -> Self {
        Self {
            interfaces: Vec::new(),
            addresses: Vec::new(),
            routes: Vec::new(),
            neighbors: Vec::new(),
            gateways: Vec::new(),
            dns: DnsConfiguration::default(),
            generation: 0,
        }
    }
}

impl NetworkStateSnapshot {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn interface_count(&self) -> usize {
        self.interfaces.len()
    }

    pub fn address_count(&self) -> usize {
        self.addresses.len()
    }

    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    pub fn neighbor_count(&self) -> usize {
        self.neighbors.len()
    }

    pub fn gateway_count(&self) -> usize {
        self.gateways.len()
    }

    pub fn is_empty(&self) -> bool {
        self.interfaces.is_empty()
            && self.addresses.is_empty()
            && self.routes.is_empty()
            && self.neighbors.is_empty()
            && self.gateways.is_empty()
            && self.dns.servers.is_empty()
    }

    pub fn clear(&mut self) {
        self.interfaces.clear();
        self.addresses.clear();
        self.routes.clear();
        self.neighbors.clear();
        self.gateways.clear();
        self.dns.clear();
        self.generation = self.generation.saturating_add(1);
    }

    pub fn find_interface(
        &self,
        id: u64,
    ) -> Option<&InterfaceInfo> {
        self.interfaces.iter().find(|x| x.id == id)
    }

    pub fn find_route(
        &self,
        id: u64,
    ) -> Option<&RouteInfo> {
        self.routes.iter().find(|x| x.id == id)
    }

    pub fn find_address(
        &self,
        address: std::net::IpAddr,
    ) -> Option<&AddressInfo> {
        self.addresses
            .iter()
            .find(|x| x.address == address)
    }

    pub fn find_neighbor(
        &self,
        address: std::net::IpAddr,
    ) -> Option<&NeighborInfo> {
        self.neighbors
            .iter()
            .find(|x| x.ip_address == address)
    }

    pub fn find_gateway(
        &self,
        address: std::net::IpAddr,
    ) -> Option<&GatewayInfo> {
        self.gateways
            .iter()
            .find(|x| x.address == address)
    }
}

#[derive(Debug)]
pub struct NetworkState {
    snapshot: RwLock<NetworkStateSnapshot>,
}

impl NetworkState {
    pub fn new() -> Self {
        Self {
            snapshot: RwLock::new(
                NetworkStateSnapshot::default(),
            ),
        }
    }

    pub fn snapshot(
        &self,
    ) -> NetworkStateSnapshot {
        self.snapshot
            .read()
            .expect("network state lock poisoned")
            .clone()
    }

    pub fn generation(&self) -> u64 {
        self.snapshot
            .read()
            .expect("network state lock poisoned")
            .generation
    }

    pub fn replace(
        &self,
        mut snapshot: NetworkStateSnapshot,
    ) {
        let mut current = self
            .snapshot
            .write()
            .expect("network state lock poisoned");

        snapshot.generation =
            current.generation.saturating_add(1);

        *current = snapshot;
    }

    pub fn clear(&self) {
        let mut state = self
            .snapshot
            .write()
            .expect("network state lock poisoned");

        state.interfaces.clear();
        state.addresses.clear();
        state.routes.clear();
        state.neighbors.clear();
        state.gateways.clear();
        state.dns.clear();

        state.generation =
            state.generation.saturating_add(1);
    }

    pub fn set_interfaces(
        &self,
        interfaces: Vec<InterfaceInfo>,
    ) {
        let mut state = self
            .snapshot
            .write()
            .expect("network state lock poisoned");

        state.interfaces = interfaces;
        state.generation =
            state.generation.saturating_add(1);
    }

    pub fn set_addresses(
        &self,
        addresses: Vec<AddressInfo>,
    ) {
        let mut state = self
            .snapshot
            .write()
            .expect("network state lock poisoned");

        state.addresses = addresses;
        state.generation =
            state.generation.saturating_add(1);
    }

    pub fn set_routes(
        &self,
        routes: Vec<RouteInfo>,
    ) {
        let mut state = self
            .snapshot
            .write()
            .expect("network state lock poisoned");

        state.routes = routes;
        state.generation =
            state.generation.saturating_add(1);
    }

    pub fn set_neighbors(
        &self,
        neighbors: Vec<NeighborInfo>,
    ) {
        let mut state = self
            .snapshot
            .write()
            .expect("network state lock poisoned");

        state.neighbors = neighbors;
        state.generation =
            state.generation.saturating_add(1);
    }

    pub fn set_gateways(
        &self,
        gateways: Vec<GatewayInfo>,
    ) {
        let mut state = self
            .snapshot
            .write()
            .expect("network state lock poisoned");

        state.gateways = gateways;
        state.generation =
            state.generation.saturating_add(1);
    }

    pub fn set_dns(
        &self,
        dns: DnsConfiguration,
    ) {
        let mut state = self
            .snapshot
            .write()
            .expect("network state lock poisoned");

        state.dns = dns;
        state.generation =
            state.generation.saturating_add(1);
    }

    pub fn update<F>(
        &self,
        updater: F,
    )
    where
        F: FnOnce(
            &mut NetworkStateSnapshot,
        ),
    {
        let mut state = self
            .snapshot
            .write()
            .expect("network state lock poisoned");

        updater(&mut state);

        state.generation =
            state.generation.saturating_add(1);
    }

    pub fn interface(
        &self,
        id: u64,
    ) -> Option<InterfaceInfo> {
        self.snapshot
            .read()
            .expect("network state lock poisoned")
            .find_interface(id)
            .cloned()
    }

    pub fn route(
        &self,
        id: u64,
    ) -> Option<RouteInfo> {
        self.snapshot
            .read()
            .expect("network state lock poisoned")
            .find_route(id)
            .cloned()
    }

    pub fn address(
        &self,
        address: std::net::IpAddr,
    ) -> Option<AddressInfo> {
        self.snapshot
            .read()
            .expect("network state lock poisoned")
            .find_address(address)
            .cloned()
    }

    pub fn neighbor(
        &self,
        address: std::net::IpAddr,
    ) -> Option<NeighborInfo> {
        self.snapshot
            .read()
            .expect("network state lock poisoned")
            .find_neighbor(address)
            .cloned()
    }

    pub fn gateway(
        &self,
        address: std::net::IpAddr,
    ) -> Option<GatewayInfo> {
        self.snapshot
            .read()
            .expect("network state lock poisoned")
            .find_gateway(address)
            .cloned()
    }

    pub fn interface_count(&self) -> usize {
        self.snapshot()
            .interface_count()
    }

    pub fn route_count(&self) -> usize {
        self.snapshot()
            .route_count()
    }

    pub fn address_count(&self) -> usize {
        self.snapshot()
            .address_count()
    }

    pub fn neighbor_count(&self) -> usize {
        self.snapshot()
            .neighbor_count()
    }

    pub fn gateway_count(&self) -> usize {
        self.snapshot()
            .gateway_count()
    }
}

impl Default for NetworkState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn creates_empty_state() {
        let state = NetworkState::new();

        assert_eq!(
            state.interface_count(),
            0
        );

        assert_eq!(
            state.route_count(),
            0
        );

        assert_eq!(
            state.address_count(),
            0
        );

        assert_eq!(
            state.neighbor_count(),
            0
        );

        assert_eq!(
            state.gateway_count(),
            0
        );

        assert_eq!(
            state.generation(),
            0
        );
    }

    #[test]
    fn dns_configuration() {
        let mut dns =
            DnsConfiguration::new();

        assert!(!dns.is_configured());

        dns.add_server(
            "1.1.1.1".parse().unwrap()
        );

        assert!(dns.is_configured());
        assert_eq!(
            dns.servers.len(),
            1
        );

        dns.add_server(
            "1.1.1.1".parse().unwrap()
        );

        assert_eq!(
            dns.servers.len(),
            1
        );

        assert!(
            dns.remove_server(
                "1.1.1.1".parse().unwrap()
            )
        );

        assert!(!dns.is_configured());
    }

    #[test]
    fn replace_updates_generation() {
        let state = NetworkState::new();

        let mut snapshot =
            NetworkStateSnapshot::new();

        snapshot.interfaces.push(
            InterfaceInfo::new(
                1,
                "Ethernet",
            )
        );

        state.replace(snapshot);

        assert_eq!(
            state.interface_count(),
            1
        );

        assert_eq!(
            state.generation(),
            1
        );
    }

    #[test]
    fn setters_update_state() {
        let state = NetworkState::new();

        let interface =
            InterfaceInfo::new(
                10,
                "Ethernet",
            );

        state.set_interfaces(
            vec![interface]
        );

        assert_eq!(
            state.interface_count(),
            1
        );

        let address =
            AddressInfo::new(
                10,
                IpAddr::V4(
                    Ipv4Addr::new(
                        192,
                        168,
                        1,
                        10,
                    )
                ),
                24,
            )
            .unwrap();

        state.set_addresses(
            vec![address]
        );

        assert_eq!(
            state.address_count(),
            1
        );

        assert!(
            state.address(
                "192.168.1.10"
                    .parse()
                    .unwrap()
            )
            .is_some()
        );
    }

    #[test]
    fn update_mutates_state() {
        let state = NetworkState::new();

        state.update(|snapshot| {
            snapshot.dns.add_server(
                "8.8.8.8"
                    .parse()
                    .unwrap()
            );
        });

        let snapshot =
            state.snapshot();

        assert_eq!(
            snapshot.dns.servers.len(),
            1
        );

        assert_eq!(
            snapshot.generation,
            1
        );
    }

    #[test]
    fn clear_removes_all_state() {
        let state = NetworkState::new();

        state.update(|snapshot| {
            snapshot.interfaces.push(
                InterfaceInfo::new(
                    1,
                    "Ethernet",
                )
            );

            snapshot.dns.add_server(
                "1.1.1.1"
                    .parse()
                    .unwrap()
            );
        });

        state.clear();

        let snapshot =
            state.snapshot();

        assert!(snapshot.is_empty());
        assert_eq!(
            snapshot.generation,
            2
        );
    }

    #[test]
    fn snapshot_is_independent() {
        let state = NetworkState::new();

        state.set_interfaces(
            vec![
                InterfaceInfo::new(
                    1,
                    "Ethernet",
                )
            ]
        );

        let mut snapshot =
            state.snapshot();

        snapshot.interfaces.clear();

        assert_eq!(
            state.interface_count(),
            1
        );
    }
}