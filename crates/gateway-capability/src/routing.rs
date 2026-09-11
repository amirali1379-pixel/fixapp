use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingEntry {
    pub destination: IpAddr,
    pub prefix_len: u8,
    pub next_hop: Option<IpAddr>,
    pub interface_id: u32,
    pub metric: u32,
    pub enabled: bool,
}

impl RoutingEntry {
    pub fn new(
        destination: IpAddr,
        prefix_len: u8,
        next_hop: Option<IpAddr>,
        interface_id: u32,
        metric: u32,
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
            next_hop,
            interface_id,
            metric,
            enabled: true,
        })
    }

    pub fn matches(&self, address: IpAddr) -> bool {
        match (self.destination, address) {
            (IpAddr::V4(network), IpAddr::V4(addr)) => {
                ipv4_matches(network, addr, self.prefix_len)
            }

            (IpAddr::V6(network), IpAddr::V6(addr)) => {
                ipv6_matches(network, addr, self.prefix_len)
            }

            _ => false,
        }
    }

    pub fn prefix_length(&self) -> u8 {
        self.prefix_len
    }
}

#[derive(Debug, Default)]
pub struct RoutingTable {
    entries: Vec<RoutingEntry>,
}

impl RoutingTable {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn add(&mut self, entry: RoutingEntry) {
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

    pub fn entries(&self) -> &[RoutingEntry] {
        &self.entries
    }

    /// Longest-prefix-match first.
    ///
    /// If multiple routes have the same prefix length,
    /// the route with the lowest metric wins.
    pub fn best(&self, destination: IpAddr) -> Option<&RoutingEntry> {
        self.entries
            .iter()
            .filter(|entry| {
                entry.enabled && entry.matches(destination)
            })
            .max_by(|a, b| {
                a.prefix_len
                    .cmp(&b.prefix_len)
                    .then_with(|| b.metric.cmp(&a.metric))
            })
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
}

fn ipv4_matches(
    network: std::net::Ipv4Addr,
    address: std::net::Ipv4Addr,
    prefix_len: u8,
) -> bool {
    if prefix_len == 0 {
        return true;
    }

    let network = u32::from(network);
    let address = u32::from(address);

    let mask = u32::MAX << (32 - prefix_len);

    (network & mask) == (address & mask)
}

fn ipv6_matches(
    network: std::net::Ipv6Addr,
    address: std::net::Ipv6Addr,
    prefix_len: u8,
) -> bool {
    if prefix_len == 0 {
        return true;
    }

    let network = u128::from(network);
    let address = u128::from(address);

    let mask = u128::MAX << (128 - prefix_len);

    (network & mask) == (address & mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn ipv4_default_route_matches_everything() {
        let entry = RoutingEntry::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            0,
            None,
            1,
            100,
        )
        .unwrap();

        assert!(entry.matches(IpAddr::V4(
            Ipv4Addr::new(192, 168, 1, 50)
        )));
    }

    #[test]
    fn ipv4_prefix_matching() {
        let entry = RoutingEntry::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
            24,
            None,
            1,
            10,
        )
        .unwrap();

        assert!(entry.matches(IpAddr::V4(
            Ipv4Addr::new(192, 168, 1, 10)
        )));

        assert!(!entry.matches(IpAddr::V4(
            Ipv4Addr::new(192, 168, 2, 10)
        )));
    }

    #[test]
    fn longest_prefix_wins() {
        let mut table = RoutingTable::new();

        table.add(
            RoutingEntry::new(
                IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                0,
                Some(IpAddr::V4(Ipv4Addr::new(
                    10, 0, 0, 1,
                ))),
                1,
                1,
            )
            .unwrap(),
        );

        table.add(
            RoutingEntry::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
                16,
                Some(IpAddr::V4(Ipv4Addr::new(
                    10, 0, 0, 2,
                ))),
                2,
                100,
            )
            .unwrap(),
        );

        table.add(
            RoutingEntry::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
                24,
                Some(IpAddr::V4(Ipv4Addr::new(
                    10, 0, 0, 3,
                ))),
                3,
                200,
            )
            .unwrap(),
        );

        let route = table
            .best(IpAddr::V4(Ipv4Addr::new(
                192, 168, 1, 50,
            )))
            .unwrap();

        assert_eq!(route.prefix_len, 24);
        assert_eq!(route.interface_id, 3);
    }

    #[test]
    fn metric_breaks_same_prefix_tie() {
        let mut table = RoutingTable::new();

        table.add(
            RoutingEntry::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                24,
                None,
                1,
                50,
            )
            .unwrap(),
        );

        table.add(
            RoutingEntry::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                24,
                None,
                2,
                10,
            )
            .unwrap(),
        );

        let route = table
            .best(IpAddr::V4(Ipv4Addr::new(
                10, 0, 0, 42,
            )))
            .unwrap();

        assert_eq!(route.interface_id, 2);
        assert_eq!(route.metric, 10);
    }

    #[test]
    fn disabled_route_is_ignored() {
        let mut table = RoutingTable::new();

        table.add(
            RoutingEntry::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                24,
                None,
                1,
                1,
            )
            .unwrap(),
        );

        assert!(table.set_enabled(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            24,
            1,
            false,
        ));

        assert!(table
            .best(IpAddr::V4(Ipv4Addr::new(
                10, 0, 0, 5
            )))
            .is_none());
    }

    #[test]
    fn ipv6_prefix_matching() {
        let entry = RoutingEntry::new(
            IpAddr::V6(Ipv6Addr::new(
                0x2001,
                0xdb8,
                0,
                0,
                0,
                0,
                0,
                0,
            )),
            32,
            None,
            1,
            1,
        )
        .unwrap();

        assert!(entry.matches(IpAddr::V6(
            Ipv6Addr::new(
                0x2001,
                0xdb8,
                0x1234,
                0,
                0,
                0,
                0,
                1,
            )
        )));

        assert!(!entry.matches(IpAddr::V6(
            Ipv6Addr::new(
                0x2001,
                0xdb9,
                0,
                0,
                0,
                0,
                0,
                1,
            )
        )));
    }

    #[test]
    fn invalid_prefix_is_rejected() {
        assert!(
            RoutingEntry::new(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                33,
                None,
                1,
                1,
            )
            .is_none()
        );

        assert!(
            RoutingEntry::new(
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                129,
                None,
                1,
                1,
            )
            .is_none()
        );
    }
}