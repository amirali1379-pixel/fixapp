use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterType {
    Ethernet,
    Wifi,
    Loopback,
    Tunnel,
    Other,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterState {
    Up,
    Down,
    Testing,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterAddress {
    pub address: IpAddr,
    pub prefix_length: u8,
}

impl AdapterAddress {
    pub fn new(address: IpAddr, prefix_length: u8) -> Option<Self> {
        let maximum = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        if prefix_length > maximum {
            return None;
        }

        Some(Self {
            address,
            prefix_length,
        })
    }

    #[inline]
    pub fn is_ipv4(&self) -> bool {
        self.address.is_ipv4()
    }

    #[inline]
    pub fn is_ipv6(&self) -> bool {
        self.address.is_ipv6()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterInfo {
    /// Stable Windows interface index when known.
    ///
    /// This value must come from Windows IP Helper/networking APIs.
    /// It must never be fabricated from Npcap enumeration order.
    ///
    /// `0` is reserved internally for an adapter whose Windows
    /// interface index has not been resolved yet.
    pub index: u32,

    /// Native Npcap device name / Windows adapter identity.
    ///
    /// This is the value that can be passed to `pcap_open_live`.
    pub name: String,

    /// Human-readable adapter description.
    pub description: String,

    pub adapter_type: AdapterType,

    pub state: AdapterState,

    pub mac_address: Option<[u8; 6]>,

    pub mtu: u32,

    pub addresses: Vec<AdapterAddress>,
}

impl AdapterInfo {
    /// Creates an adapter with a known Windows interface index.
    pub fn new(index: u32, name: impl Into<String>) -> Option<Self> {
        if index == 0 {
            return None;
        }

        Self::new_internal(index, name)
    }

    /// Creates an adapter discovered through Npcap before IP Helper
    /// has resolved its Windows interface index.
    ///
    /// The returned `index` is intentionally `0`. It is a sentinel
    /// meaning "Windows interface index not resolved yet".
    ///
    /// No fake index is generated from Npcap enumeration order.
    pub fn from_npcap(name: impl Into<String>) -> Option<Self> {
        Self::new_internal(0, name)
    }

    fn new_internal(index: u32, name: impl Into<String>) -> Option<Self> {
        let name = name.into();

        if name.trim().is_empty() {
            return None;
        }

        Some(Self {
            index,
            name,
            description: String::new(),
            adapter_type: AdapterType::Unknown,
            state: AdapterState::Unknown,
            mac_address: None,
            mtu: 0,
            addresses: Vec::new(),
        })
    }

    /// Returns whether the Windows interface index has been resolved.
    #[inline]
    pub fn has_interface_index(&self) -> bool {
        self.index != 0
    }

    /// Assigns the real Windows interface index obtained from
    /// IP Helper.
    ///
    /// `0` is rejected because it represents an unresolved index.
    pub fn set_interface_index(&mut self, index: u32) -> bool {
        if index == 0 {
            return false;
        }

        self.index = index;
        true
    }

    #[inline]
    pub fn set_description(&mut self, description: impl Into<String>) {
        self.description = description.into();
    }

    #[inline]
    pub fn set_type(&mut self, adapter_type: AdapterType) {
        self.adapter_type = adapter_type;
    }

    #[inline]
    pub fn set_state(&mut self, state: AdapterState) {
        self.state = state;
    }

    #[inline]
    pub fn set_mtu(&mut self, mtu: u32) {
        self.mtu = mtu;
    }

    pub fn add_address(&mut self, address: AdapterAddress) {
        if !self.addresses.iter().any(|existing| existing == &address) {
            self.addresses.push(address);
        }
    }

    pub fn set_mac(&mut self, mac: [u8; 6]) {
        self.mac_address = Some(mac);
    }

    #[inline]
    pub fn has_mac(&self) -> bool {
        self.mac_address.is_some()
    }

    #[inline]
    pub fn is_up(&self) -> bool {
        self.state == AdapterState::Up
    }

    #[inline]
    pub fn is_down(&self) -> bool {
        self.state == AdapterState::Down
    }

    #[inline]
    pub fn supports_ipv4(&self) -> bool {
        self.addresses.iter().any(AdapterAddress::is_ipv4)
    }

    #[inline]
    pub fn supports_ipv6(&self) -> bool {
        self.addresses.iter().any(AdapterAddress::is_ipv6)
    }

    #[inline]
    pub fn address_count(&self) -> usize {
        self.addresses.len()
    }

    #[inline]
    pub fn is_loopback(&self) -> bool {
        self.adapter_type == AdapterType::Loopback
    }

    #[inline]
    pub fn is_wireless(&self) -> bool {
        self.adapter_type == AdapterType::Wifi
    }

    #[inline]
    pub fn is_tunnel(&self) -> bool {
        self.adapter_type == AdapterType::Tunnel
    }

    /// Returns the native Npcap device identifier.
    ///
    /// This value is passed to `pcap_open_live`.
    #[inline]
    pub fn npcap_name(&self) -> &str {
        &self.name
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterTableError {
    InvalidAdapterIndex,
    AdapterNotFound,
}

#[derive(Debug, Default)]
pub struct AdapterTable {
    adapters: Vec<AdapterInfo>,
}

impl AdapterTable {
    pub fn new() -> Self {
        Self {
            adapters: Vec::new(),
        }
    }

    /// Inserts an adapter with a resolved Windows interface index.
    ///
    /// Index `0` is reserved for unresolved Npcap-only adapters and
    /// therefore cannot be inserted into the indexed table.
    pub fn insert(&mut self, adapter: AdapterInfo) -> Result<(), AdapterTableError> {
        if adapter.index == 0 {
            return Err(AdapterTableError::InvalidAdapterIndex);
        }

        if let Some(existing) = self
            .adapters
            .iter_mut()
            .find(|existing| existing.index == adapter.index)
        {
            *existing = adapter;
        } else {
            self.adapters.push(adapter);
        }

        self.adapters.sort_by_key(|adapter| adapter.index);

        Ok(())
    }

    pub fn get(&self, index: u32) -> Result<&AdapterInfo, AdapterTableError> {
        if index == 0 {
            return Err(AdapterTableError::InvalidAdapterIndex);
        }

        self.adapters
            .iter()
            .find(|adapter| adapter.index == index)
            .ok_or(AdapterTableError::AdapterNotFound)
    }

    pub fn get_mut(&mut self, index: u32) -> Result<&mut AdapterInfo, AdapterTableError> {
        if index == 0 {
            return Err(AdapterTableError::InvalidAdapterIndex);
        }

        self.adapters
            .iter_mut()
            .find(|adapter| adapter.index == index)
            .ok_or(AdapterTableError::AdapterNotFound)
    }

    pub fn remove(&mut self, index: u32) -> Result<AdapterInfo, AdapterTableError> {
        if index == 0 {
            return Err(AdapterTableError::InvalidAdapterIndex);
        }

        let position = self
            .adapters
            .iter()
            .position(|adapter| adapter.index == index)
            .ok_or(AdapterTableError::AdapterNotFound)?;

        Ok(self.adapters.remove(position))
    }

    #[inline]
    pub fn all(&self) -> &[AdapterInfo] {
        &self.adapters
    }

    #[inline]
    pub fn clear(&mut self) {
        self.adapters.clear();
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.adapters.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.adapters.is_empty()
    }

    pub fn find_by_name(&self, name: &str) -> Option<&AdapterInfo> {
        self.adapters
            .iter()
            .find(|adapter| adapter.name == name)
    }

    pub fn find_by_name_mut(&mut self, name: &str) -> Option<&mut AdapterInfo> {
        self.adapters
            .iter_mut()
            .find(|adapter| adapter.name == name)
    }

    pub fn find_up(&self) -> impl Iterator<Item = &AdapterInfo> {
        self.adapters.iter().filter(|adapter| adapter.is_up())
    }

    pub fn find_ipv4(&self) -> impl Iterator<Item = &AdapterInfo> {
        self.adapters
            .iter()
            .filter(|adapter| adapter.supports_ipv4())
    }

    pub fn find_ipv6(&self) -> impl Iterator<Item = &AdapterInfo> {
        self.adapters
            .iter()
            .filter(|adapter| adapter.supports_ipv6())
    }

    pub fn find_resolved(&self) -> impl Iterator<Item = &AdapterInfo> {
        self.adapters
            .iter()
            .filter(|adapter| adapter.has_interface_index())
    }

    pub fn find_by_npcap_name(&self, name: &str) -> Option<&AdapterInfo> {
        self.adapters
            .iter()
            .find(|adapter| adapter.npcap_name() == name)
    }

    pub fn find_by_npcap_name_mut(&mut self, name: &str) -> Option<&mut AdapterInfo> {
        self.adapters
            .iter_mut()
            .find(|adapter| adapter.npcap_name() == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn creates_adapter() {
        let adapter = AdapterInfo::new(1, "Ethernet").unwrap();

        assert_eq!(adapter.index, 1);
        assert_eq!(adapter.name, "Ethernet");
        assert_eq!(adapter.adapter_type, AdapterType::Unknown);
        assert_eq!(adapter.state, AdapterState::Unknown);
        assert!(adapter.has_interface_index());
    }

    #[test]
    fn creates_npcap_adapter_without_fake_index() {
        let adapter =
            AdapterInfo::from_npcap(r"\Device\NPF_{TEST}").unwrap();

        assert_eq!(adapter.index, 0);
        assert!(!adapter.has_interface_index());
        assert_eq!(
            adapter.npcap_name(),
            r"\Device\NPF_{TEST}"
        );
    }

    #[test]
    fn resolves_npcap_adapter_index() {
        let mut adapter =
            AdapterInfo::from_npcap(r"\Device\NPF_{TEST}").unwrap();

        assert!(adapter.set_interface_index(7));
        assert_eq!(adapter.index, 7);
        assert!(adapter.has_interface_index());
    }

    #[test]
    fn rejects_zero_index() {
        assert!(
            AdapterInfo::new(0, "Ethernet").is_none()
        );
    }

    #[test]
    fn rejects_empty_name() {
        assert!(
            AdapterInfo::new(1, "   ").is_none()
        );
    }

    #[test]
    fn accepts_ipv4_address() {
        let address = AdapterAddress::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            24,
        )
        .unwrap();

        assert!(address.is_ipv4());
        assert!(!address.is_ipv6());
    }

    #[test]
    fn accepts_ipv6_address() {
        let address = AdapterAddress::new(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            128,
        )
        .unwrap();

        assert!(!address.is_ipv4());
        assert!(address.is_ipv6());
    }

    #[test]
    fn rejects_invalid_ipv4_prefix() {
        assert!(
            AdapterAddress::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                33,
            )
            .is_none()
        );
    }

    #[test]
    fn rejects_invalid_ipv6_prefix() {
        assert!(
            AdapterAddress::new(
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                129,
            )
            .is_none()
        );
    }

    #[test]
    fn deduplicates_addresses() {
        let address = AdapterAddress::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8,
        )
        .unwrap();

        let mut adapter =
            AdapterInfo::new(1, "Loopback").unwrap();

        adapter.add_address(address.clone());
        adapter.add_address(address);

        assert_eq!(adapter.addresses.len(), 1);
    }

    #[test]
    fn detects_ipv4_support() {
        let address = AdapterAddress::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8,
        )
        .unwrap();

        let mut adapter =
            AdapterInfo::new(1, "Loopback").unwrap();

        adapter.add_address(address);

        assert!(adapter.supports_ipv4());
        assert!(!adapter.supports_ipv6());
    }

    #[test]
    fn detects_ipv6_support() {
        let address = AdapterAddress::new(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            128,
        )
        .unwrap();

        let mut adapter =
            AdapterInfo::new(1, "Loopback").unwrap();

        adapter.add_address(address);

        assert!(!adapter.supports_ipv4());
        assert!(adapter.supports_ipv6());
    }

    #[test]
    fn adapter_table_insert_and_get() {
        let mut table = AdapterTable::new();

        table
            .insert(AdapterInfo::new(2, "Ethernet").unwrap())
            .unwrap();

        let adapter = table.get(2).unwrap();

        assert_eq!(adapter.name, "Ethernet");
    }

    #[test]
    fn adapter_table_updates_existing_index() {
        let mut table = AdapterTable::new();

        table
            .insert(AdapterInfo::new(1, "old").unwrap())
            .unwrap();

        table
            .insert(AdapterInfo::new(1, "new").unwrap())
            .unwrap();

        assert_eq!(table.len(), 1);
        assert_eq!(table.get(1).unwrap().name, "new");
    }

    #[test]
    fn adapter_table_remove() {
        let mut table = AdapterTable::new();

        table
            .insert(AdapterInfo::new(1, "Ethernet").unwrap())
            .unwrap();

        let removed = table.remove(1).unwrap();

        assert_eq!(removed.name, "Ethernet");
        assert!(table.is_empty());
    }

    #[test]
    fn adapter_table_rejects_zero_index() {
        let mut table = AdapterTable::new();

        let adapter = AdapterInfo {
            index: 0,
            name: "invalid".to_string(),
            description: String::new(),
            adapter_type: AdapterType::Unknown,
            state: AdapterState::Unknown,
            mac_address: None,
            mtu: 0,
            addresses: Vec::new(),
        };

        assert_eq!(
            table.insert(adapter),
            Err(AdapterTableError::InvalidAdapterIndex)
        );
    }

    #[test]
    fn adapter_table_is_sorted_by_interface_index() {
        let mut table = AdapterTable::new();

        table
            .insert(AdapterInfo::new(10, "ten").unwrap())
            .unwrap();

        table
            .insert(AdapterInfo::new(2, "two").unwrap())
            .unwrap();

        assert_eq!(table.all()[0].index, 2);
        assert_eq!(table.all()[1].index, 10);
    }

    #[test]
    fn finds_adapter_by_native_name() {
        let mut table = AdapterTable::new();

        table
            .insert(
                AdapterInfo::new(
                    7,
                    r"\Device\NPF_{TEST}",
                )
                .unwrap(),
            )
            .unwrap();

        assert!(
            table
                .find_by_name(r"\Device\NPF_{TEST}")
                .is_some()
        );
    }

    #[test]
    fn finds_up_adapters() {
        let mut table = AdapterTable::new();

        let mut up =
            AdapterInfo::new(1, "up").unwrap();

        up.set_state(AdapterState::Up);

        let down =
            AdapterInfo::new(2, "down").unwrap();

        table.insert(up).unwrap();
        table.insert(down).unwrap();

        let result: Vec<u32> = table
            .find_up()
            .map(|adapter| adapter.index)
            .collect();

        assert_eq!(result, vec![1]);
    }

    #[test]
    fn finds_resolved_adapters() {
        let mut table = AdapterTable::new();

        table
            .insert(AdapterInfo::new(1, "resolved").unwrap())
            .unwrap();

        let resolved: Vec<u32> = table
            .find_resolved()
            .map(|adapter| adapter.index)
            .collect();

        assert_eq!(resolved, vec![1]);
    }
}