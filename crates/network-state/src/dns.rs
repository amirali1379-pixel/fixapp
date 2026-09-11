use std::net::IpAddr;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsServer {
    pub address: IpAddr,
    pub interface_id: Option<u32>,
}

impl DnsServer {
    pub fn new(
        address: IpAddr,
        interface_id: Option<u32>,
    ) -> Self {
        Self {
            address,
            interface_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsConfig {
    pub servers: Vec<DnsServer>,
    pub search_domains: Vec<String>,
    pub updated_at: SystemTime,
}

impl DnsConfig {
    pub fn new() -> Self {
        Self {
            servers: Vec::new(),
            search_domains: Vec::new(),
            updated_at: SystemTime::now(),
        }
    }

    pub fn with_servers(
        servers: Vec<DnsServer>,
    ) -> Self {
        Self {
            servers,
            search_domains: Vec::new(),
            updated_at: SystemTime::now(),
        }
    }

    pub fn set_servers(
        &mut self,
        servers: Vec<DnsServer>,
    ) {
        self.servers = servers;
        self.touch();
    }

    pub fn add_server(
        &mut self,
        server: DnsServer,
    ) {
        if !self
            .servers
            .iter()
            .any(|existing| existing == &server)
        {
            self.servers.push(server);
            self.touch();
        }
    }

    pub fn remove_server(
        &mut self,
        address: &IpAddr,
        interface_id: Option<u32>,
    ) -> bool {
        let old_len = self.servers.len();

        self.servers.retain(|server| {
            !(server.address == *address
                && server.interface_id == interface_id)
        });

        let removed = self.servers.len() != old_len;

        if removed {
            self.touch();
        }

        removed
    }

    pub fn set_search_domains(
        &mut self,
        domains: Vec<String>,
    ) {
        self.search_domains = domains
            .into_iter()
            .filter(|domain| !domain.trim().is_empty())
            .collect();

        self.touch();
    }

    pub fn add_search_domain(
        &mut self,
        domain: &str,
    ) {
        let domain = domain.trim();

        if domain.is_empty() {
            return;
        }

        if !self
            .search_domains
            .iter()
            .any(|existing| existing == domain)
        {
            self.search_domains
                .push(domain.to_string());

            self.touch();
        }
    }

    pub fn clear(&mut self) {
        self.servers.clear();
        self.search_domains.clear();
        self.touch();
    }

    pub fn server_count(&self) -> usize {
        self.servers.len()
    }

    pub fn has_servers(&self) -> bool {
        !self.servers.is_empty()
    }

    pub fn servers_for_interface(
        &self,
        interface_id: u32,
    ) -> Vec<IpAddr> {
        self.servers
            .iter()
            .filter_map(|server| {
                match server.interface_id {
                    Some(id) if id == interface_id => {
                        Some(server.address)
                    }
                    None => Some(server.address),
                    _ => None,
                }
            })
            .collect()
    }

    pub fn age(&self) -> Duration {
        SystemTime::now()
            .duration_since(self.updated_at)
            .unwrap_or_default()
    }

    fn touch(&mut self) {
        self.updated_at = SystemTime::now();
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn server() -> DnsServer {
        DnsServer::new(
            IpAddr::V4(Ipv4Addr::new(
                8, 8, 8, 8,
            )),
            Some(1),
        )
    }

    #[test]
    fn creates_empty_config() {
        let config = DnsConfig::new();

        assert!(config.servers.is_empty());
        assert!(config.search_domains.is_empty());
        assert!(!config.has_servers());
    }

    #[test]
    fn adds_server() {
        let mut config =
            DnsConfig::new();

        config.add_server(server());

        assert_eq!(
            config.server_count(),
            1
        );

        assert!(config.has_servers());
    }

    #[test]
    fn duplicate_server_is_not_added() {
        let mut config =
            DnsConfig::new();

        config.add_server(server());
        config.add_server(server());

        assert_eq!(
            config.server_count(),
            1
        );
    }

    #[test]
    fn removes_server() {
        let mut config =
            DnsConfig::new();

        config.add_server(server());

        let removed = config.remove_server(
            &IpAddr::V4(
                Ipv4Addr::new(
                    8, 8, 8, 8,
                ),
            ),
            Some(1),
        );

        assert!(removed);
        assert!(!config.has_servers());
    }

    #[test]
    fn adds_search_domain() {
        let mut config =
            DnsConfig::new();

        config.add_search_domain(
            "example.local",
        );

        assert_eq!(
            config.search_domains.len(),
            1
        );

        assert_eq!(
            config.search_domains[0],
            "example.local"
        );
    }

    #[test]
    fn empty_search_domain_is_ignored() {
        let mut config =
            DnsConfig::new();

        config.add_search_domain("   ");

        assert!(
            config.search_domains.is_empty()
        );
    }

    #[test]
    fn duplicate_search_domain_is_not_added() {
        let mut config =
            DnsConfig::new();

        config.add_search_domain(
            "example.local",
        );

        config.add_search_domain(
            "example.local",
        );

        assert_eq!(
            config.search_domains.len(),
            1
        );
    }

    #[test]
    fn interface_lookup_includes_global_servers() {
        let mut config =
            DnsConfig::new();

        config.add_server(
            DnsServer::new(
                IpAddr::V4(
                    Ipv4Addr::new(
                        1, 1, 1, 1,
                    ),
                ),
                None,
            ),
        );

        config.add_server(server());

        let servers =
            config.servers_for_interface(1);

        assert_eq!(
            servers.len(),
            2
        );
    }

    #[test]
    fn clear_removes_all_dns_state() {
        let mut config =
            DnsConfig::new();

        config.add_server(server());
        config.add_search_domain(
            "example.local",
        );

        config.clear();

        assert!(
            config.servers.is_empty()
        );

        assert!(
            config.search_domains.is_empty()
        );
    }

    #[test]
    fn updated_timestamp_is_available() {
        let config =
            DnsConfig::new();

        assert!(
            config.age()
                < Duration::from_secs(1)
        );
    }
}