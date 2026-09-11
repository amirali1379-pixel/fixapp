use std::net::IpAddr;

use network_state::{NetworkState, RouteInfo};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardingEntry {
    pub destination: IpAddr,
    pub prefix_len: u8,
    pub interface_id: u32,
    pub next_hop: Option<IpAddr>,
    pub enabled: bool,
}

impl ForwardingEntry {
    pub fn new(
        destination: IpAddr,
        prefix_len: u8,
        interface_id: u32,
        next_hop: Option<IpAddr>,
    ) -> Option<Self> {
        let max_prefix = match destination {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        if prefix_len > max_prefix {
            return None;
        }

        Some(Self {
            destination,
            prefix_len,
            interface_id,
            next_hop,
            enabled: true,
        })
    }

    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    pub fn matches(&self, address: IpAddr) -> bool {
        match (self.destination, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                if self.prefix_len == 0 {
                    return true;
                }

                let network = u32::from(network);
                let address = u32::from(address);
                let mask = u32::MAX << (32 - self.prefix_len);

                (network & mask) == (address & mask)
            }

            (IpAddr::V6(network), IpAddr::V6(address)) => {
                if self.prefix_len == 0 {
                    return true;
                }

                let network = u128::from(network);
                let address = u128::from(address);
                let mask = u128::MAX << (128 - self.prefix_len);

                (network & mask) == (address & mask)
            }

            _ => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardingError {
    InvalidDestination,
    NoRoute,
    InterfaceUnavailable,
    NeighborUnresolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForwardingDecision {
    pub interface_id: u32,
    pub next_hop: IpAddr,
}

#[derive(Debug, Default)]
pub struct ForwardingTable {
    entries: Vec<ForwardingEntry>,
}

impl ForwardingTable {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn add(&mut self, entry: ForwardingEntry) {
        self.entries.push(entry);
    }

    pub fn remove(
        &mut self,
        destination: IpAddr,
        prefix_len: u8,
        interface_id: u32,
    ) -> bool {
        let old_len = self.entries.len();

        self.entries.retain(|entry| {
            !(entry.destination == destination
                && entry.prefix_len == prefix_len
                && entry.interface_id == interface_id)
        });

        self.entries.len() != old_len
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[ForwardingEntry] {
        &self.entries
    }

    pub fn set_enabled(
        &mut self,
        destination: IpAddr,
        prefix_len: u8,
        interface_id: u32,
        enabled: bool,
    ) -> bool {
        for entry in &mut self.entries {
            if entry.destination == destination
                && entry.prefix_len == prefix_len
                && entry.interface_id == interface_id
            {
                entry.enabled = enabled;
                return true;
            }
        }

        false
    }

    /// Synchronize usable host/OS routes from the authoritative NetworkState.
    /// Routes whose interface is missing or non-operational are not installed.
    pub fn sync_from_network_state(
        &mut self,
        network_state: &NetworkState,
    ) -> usize {
        let snapshot = network_state.snapshot();
        let mut entries = Vec::with_capacity(snapshot.routes.len());

        for route in &snapshot.routes {
            if !route.is_usable() {
                continue;
            }

            let interface_id = match u32::try_from(route.interface_id) {
                Ok(value) if value != 0 => value,
                _ => continue,
            };

            if !snapshot
                .find_interface(route.interface_id)
                .is_some_and(|interface| interface.is_operational())
            {
                continue;
            }

            if let Some(entry) = Self::entry_from_route(route, interface_id) {
                entries.push(entry);
            }
        }

        let count = entries.len();
        self.entries = entries;
        count
    }

    /// Returns the most specific enabled forwarding entry.
    ///
    /// If multiple entries have the same prefix length, the first
    /// configured entry wins.
    pub fn lookup(&self, destination: IpAddr) -> Option<&ForwardingEntry> {
        self.entries
            .iter()
            .filter(|entry| {
                entry.enabled && entry.matches(destination)
            })
            .max_by_key(|entry| entry.prefix_len)
    }

    /// Resolve a forwarding decision.
    pub fn resolve(
        &self,
        destination: IpAddr,
    ) -> Result<ForwardingDecision, ForwardingError> {
        let entry = self
            .lookup(destination)
            .ok_or(ForwardingError::NoRoute)?;

        let next_hop = entry.next_hop.unwrap_or(destination);

        Ok(ForwardingDecision {
            interface_id: entry.interface_id,
            next_hop,
        })
    }

    /// Resolve using the current NetworkState and require an operational
    /// egress interface and usable next-hop neighbor.
    pub fn resolve_with_network_state(
        &self,
        destination: IpAddr,
        network_state: &NetworkState,
    ) -> Result<ForwardingDecision, ForwardingError> {
        let decision = self.resolve(destination)?;

        let interface = network_state
            .interface(u64::from(decision.interface_id))
            .ok_or(ForwardingError::InterfaceUnavailable)?;

        if !interface.is_operational() {
            return Err(ForwardingError::InterfaceUnavailable);
        }

        let neighbor = network_state
            .neighbor(decision.next_hop)
            .ok_or(ForwardingError::NeighborUnresolved)?;

        if !neighbor.is_usable() {
            return Err(ForwardingError::NeighborUnresolved);
        }

        Ok(decision)
    }

    fn entry_from_route(
        route: &RouteInfo,
        interface_id: u32,
    ) -> Option<ForwardingEntry> {
        ForwardingEntry::new(
            route.destination,
            route.prefix_length,
            interface_id,
            route.gateway,
        )
        .map(|entry| entry.with_enabled(route.enabled))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use network_state::{
        InterfaceInfo, InterfaceState, NeighborInfo, NeighborState,
        NetworkState, RouteInfo,
    };
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn lookup_uses_destination() {
        let mut table = ForwardingTable::new();

        table.add(
            ForwardingEntry::new(v4(10, 0, 0, 0), 24, 1, None).unwrap(),
        );
        table.add(
            ForwardingEntry::new(v4(192, 168, 1, 0), 24, 2, None).unwrap(),
        );

        let result = table.lookup(v4(192, 168, 1, 50));

        assert!(result.is_some());
        assert_eq!(result.unwrap().interface_id, 2);
    }

    #[test]
    fn longest_prefix_wins() {
        let mut table = ForwardingTable::new();

        table.add(
            ForwardingEntry::new(v4(10, 0, 0, 0), 8, 1, None).unwrap(),
        );
        table.add(
            ForwardingEntry::new(v4(10, 1, 0, 0), 16, 2, None).unwrap(),
        );
        table.add(
            ForwardingEntry::new(v4(10, 1, 2, 0), 24, 3, None).unwrap(),
        );

        let result = table.lookup(v4(10, 1, 2, 50)).unwrap();

        assert_eq!(result.interface_id, 3);
        assert_eq!(result.prefix_len, 24);
    }

    #[test]
    fn default_route_matches_when_specific_route_missing() {
        let mut table = ForwardingTable::new();

        table.add(
            ForwardingEntry::new(
                v4(0, 0, 0, 0),
                0,
                7,
                Some(v4(192, 168, 1, 1)),
            )
            .unwrap(),
        );

        let result = table.lookup(v4(8, 8, 8, 8)).unwrap();

        assert_eq!(result.interface_id, 7);
        assert_eq!(result.next_hop, Some(v4(192, 168, 1, 1)));
    }

    #[test]
    fn no_matching_route_returns_none() {
        let mut table = ForwardingTable::new();
        table.add(
            ForwardingEntry::new(v4(192, 168, 1, 0), 24, 1, None).unwrap(),
        );
        assert!(table.lookup(v4(10, 0, 0, 1)).is_none());
    }

    #[test]
    fn disabled_route_is_ignored() {
        let mut table = ForwardingTable::new();
        table.add(
            ForwardingEntry::new(v4(10, 0, 0, 0), 24, 1, None).unwrap(),
        );
        assert!(table.set_enabled(v4(10, 0, 0, 0), 24, 1, false));
        assert!(table.lookup(v4(10, 0, 0, 10)).is_none());
    }

    #[test]
    fn resolve_uses_explicit_next_hop() {
        let mut table = ForwardingTable::new();
        table.add(
            ForwardingEntry::new(
                v4(10, 0, 0, 0),
                24,
                5,
                Some(v4(192, 168, 1, 1)),
            )
            .unwrap(),
        );

        let decision = table.resolve(v4(10, 0, 0, 50)).unwrap();
        assert_eq!(decision.interface_id, 5);
        assert_eq!(decision.next_hop, v4(192, 168, 1, 1));
    }

    #[test]
    fn resolve_uses_destination_without_next_hop() {
        let mut table = ForwardingTable::new();
        table.add(
            ForwardingEntry::new(v4(10, 0, 0, 0), 24, 5, None).unwrap(),
        );

        let destination = v4(10, 0, 0, 50);
        let decision = table.resolve(destination).unwrap();

        assert_eq!(decision.interface_id, 5);
        assert_eq!(decision.next_hop, destination);
    }

    #[test]
    fn ipv6_lookup_works() {
        let mut table = ForwardingTable::new();
        let network = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0));

        table.add(
            ForwardingEntry::new(network, 32, 10, None).unwrap(),
        );

        let destination = IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0x1234, 0, 0, 0, 0, 1,
        ));

        let result = table.lookup(destination).unwrap();
        assert_eq!(result.interface_id, 10);
    }

    #[test]
    fn invalid_prefix_is_rejected() {
        assert!(
            ForwardingEntry::new(v4(10, 0, 0, 0), 33, 1, None).is_none()
        );
    }

    #[test]
    fn remove_entry() {
        let mut table = ForwardingTable::new();
        table.add(
            ForwardingEntry::new(v4(10, 0, 0, 0), 24, 1, None).unwrap(),
        );
        assert!(table.remove(v4(10, 0, 0, 0), 24, 1));
        assert!(table.is_empty());
    }

    #[test]
    fn syncs_routes_from_network_state() {
        let state = NetworkState::new();
        state.set_interfaces(vec![
            InterfaceInfo::new(1, "Ethernet")
                .with_state(InterfaceState::Up),
            InterfaceInfo::new(2, "Down")
                .with_state(InterfaceState::Down),
        ]);
        state.set_routes(vec![
            RouteInfo::new(1, v4(10, 0, 0, 0), 8, 1).unwrap(),
            RouteInfo::new(2, v4(192, 168, 0, 0), 16, 2).unwrap(),
        ]);

        let mut table = ForwardingTable::new();
        assert_eq!(table.sync_from_network_state(&state), 1);
        assert_eq!(table.len(), 1);
        assert_eq!(table.lookup(v4(10, 1, 2, 3)).unwrap().interface_id, 1);
        assert!(table.lookup(v4(192, 168, 1, 1)).is_none());
    }

    #[test]
    fn resolve_with_network_state_checks_interface_and_neighbor() {
        let state = NetworkState::new();
        state.set_interfaces(vec![
            InterfaceInfo::new(1, "Ethernet")
                .with_state(InterfaceState::Up),
        ]);
        state.set_neighbors(vec![
            NeighborInfo::new(1, v4(192, 168, 1, 1))
                .with_mac([0, 1, 2, 3, 4, 5])
                .with_state(NeighborState::Reachable),
        ]);

        let mut table = ForwardingTable::new();
        table.add(
            ForwardingEntry::new(
                v4(10, 0, 0, 0),
                8,
                1,
                Some(v4(192, 168, 1, 1)),
            )
            .unwrap(),
        );

        assert_eq!(
            table.resolve_with_network_state(v4(10, 1, 2, 3), &state),
            Ok(ForwardingDecision {
                interface_id: 1,
                next_hop: v4(192, 168, 1, 1),
            })
        );
    }

    #[test]
    fn unresolved_neighbor_is_explicit() {
        let state = NetworkState::new();
        state.set_interfaces(vec![
            InterfaceInfo::new(1, "Ethernet")
                .with_state(InterfaceState::Up),
        ]);

        let mut table = ForwardingTable::new();
        table.add(
            ForwardingEntry::new(
                v4(10, 0, 0, 0),
                8,
                1,
                Some(v4(192, 168, 1, 1)),
            )
            .unwrap(),
        );

        assert_eq!(
            table.resolve_with_network_state(v4(10, 1, 2, 3), &state),
            Err(ForwardingError::NeighborUnresolved)
        );
    }
}