use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketDirection {
    Inbound,
    Outbound,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Ethernet,
    Raw,
    Loopback,
    Unknown(u32),
}

impl LinkType {
    pub fn from_datalink(value: u32) -> Self {
        match value {
            1 => Self::Ethernet,
            101 => Self::Raw,
            0 => Self::Loopback,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketMetadata {
    pub interface_index: u32,
    pub direction: PacketDirection,
    pub link_type: LinkType,
    pub captured_length: usize,
    pub original_length: usize,
    pub timestamp_seconds: i64,
    pub timestamp_microseconds: i64,
    pub source_ip: Option<IpAddr>,
    pub destination_ip: Option<IpAddr>,
}

impl PacketMetadata {
    pub fn new(
        interface_index: u32,
        captured_length: usize,
        original_length: usize,
    ) -> Option<Self> {
        if interface_index == 0 {
            return None;
        }

        if captured_length == 0
            || original_length == 0
            || captured_length > original_length
        {
            return None;
        }

        Some(Self {
            interface_index,
            direction: PacketDirection::Unknown,
            link_type: LinkType::Unknown(0),
            captured_length,
            original_length,
            timestamp_seconds: 0,
            timestamp_microseconds: 0,
            source_ip: None,
            destination_ip: None,
        })
    }

    pub fn set_timestamp(
        &mut self,
        seconds: i64,
        microseconds: i64,
    ) {
        self.timestamp_seconds = seconds;
        self.timestamp_microseconds = microseconds;
    }

    pub fn set_direction(
        &mut self,
        direction: PacketDirection,
    ) {
        self.direction = direction;
    }

    pub fn set_link_type(
        &mut self,
        link_type: LinkType,
    ) {
        self.link_type = link_type;
    }

    pub fn set_endpoints(
        &mut self,
        source: IpAddr,
        destination: IpAddr,
    ) {
        self.source_ip = Some(source);
        self.destination_ip = Some(destination);
    }

    pub fn is_truncated(&self) -> bool {
        self.captured_length < self.original_length
    }

    pub fn capture_ratio(&self) -> f64 {
        if self.original_length == 0 {
            return 0.0;
        }

        self.captured_length as f64
            / self.original_length as f64
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterMetadata {
    pub interface_index: u32,
    pub name: String,
    pub description: Option<String>,
    pub mac_address: Option<[u8; 6]>,
    pub link_type: LinkType,
    pub mtu: Option<u32>,
}

impl AdapterMetadata {
    pub fn new(
        interface_index: u32,
        name: impl Into<String>,
    ) -> Option<Self> {
        if interface_index == 0 {
            return None;
        }

        let name = name.into();

        if name.trim().is_empty() {
            return None;
        }

        Some(Self {
            interface_index,
            name,
            description: None,
            mac_address: None,
            link_type: LinkType::Ethernet,
            mtu: None,
        })
    }

    pub fn set_mac(
        &mut self,
        mac: [u8; 6],
    ) {
        self.mac_address = Some(mac);
    }

    pub fn set_mtu(
        &mut self,
        mtu: u32,
    ) {
        if mtu > 0 {
            self.mtu = Some(mtu);
        }
    }

    pub fn has_mac(&self) -> bool {
        self.mac_address.is_some()
    }
}

#[derive(Debug, Default)]
pub struct MetadataTable {
    packets: Vec<PacketMetadata>,
    adapters: Vec<AdapterMetadata>,
}

impl MetadataTable {
    pub fn new() -> Self {
        Self {
            packets: Vec::new(),
            adapters: Vec::new(),
        }
    }

    pub fn add_packet(
        &mut self,
        metadata: PacketMetadata,
    ) {
        self.packets.push(metadata);
    }

    pub fn add_adapter(
        &mut self,
        metadata: AdapterMetadata,
    ) {
        if let Some(existing) =
            self.adapters.iter_mut().find(|entry| {
                entry.interface_index
                    == metadata.interface_index
            })
        {
            *existing = metadata;
            return;
        }

        self.adapters.push(metadata);
    }

    pub fn packet_metadata(
        &self,
    ) -> &[PacketMetadata] {
        &self.packets
    }

    pub fn adapters(
        &self,
    ) -> &[AdapterMetadata] {
        &self.adapters
    }

    pub fn clear_packets(&mut self) {
        self.packets.clear();
    }

    pub fn clear_adapters(&mut self) {
        self.adapters.clear();
    }

    pub fn clear(&mut self) {
        self.packets.clear();
        self.adapters.clear();
    }

    pub fn packet_count(&self) -> usize {
        self.packets.len()
    }

    pub fn adapter_count(&self) -> usize {
        self.adapters.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn creates_packet_metadata() {
        let metadata =
            PacketMetadata::new(
                1,
                100,
                100,
            );

        assert!(metadata.is_some());
    }

    #[test]
    fn rejects_invalid_packet_lengths() {
        assert!(
            PacketMetadata::new(
                1,
                101,
                100,
            )
            .is_none()
        );
    }

    #[test]
    fn detects_truncated_packet() {
        let metadata =
            PacketMetadata::new(
                1,
                64,
                128,
            )
            .unwrap();

        assert!(
            metadata.is_truncated()
        );

        assert_eq!(
            metadata.capture_ratio(),
            0.5
        );
    }

    #[test]
    fn stores_packet_endpoints() {
        let mut metadata =
            PacketMetadata::new(
                1,
                100,
                100,
            )
            .unwrap();

        let source = IpAddr::V4(
            Ipv4Addr::new(
                192, 168, 1, 10,
            ),
        );

        let destination = IpAddr::V4(
            Ipv4Addr::new(
                8, 8, 8, 8,
            ),
        );

        metadata.set_endpoints(
            source,
            destination,
        );

        assert_eq!(
            metadata.source_ip,
            Some(source)
        );

        assert_eq!(
            metadata.destination_ip,
            Some(destination)
        );
    }

    #[test]
    fn link_type_mapping_works() {
        assert_eq!(
            LinkType::from_datalink(1),
            LinkType::Ethernet
        );

        assert_eq!(
            LinkType::from_datalink(101),
            LinkType::Raw
        );
    }

    #[test]
    fn creates_adapter_metadata() {
        let adapter =
            AdapterMetadata::new(
                1,
                "Ethernet",
            );

        assert!(adapter.is_some());
    }

    #[test]
    fn adapter_can_store_mac() {
        let mut adapter =
            AdapterMetadata::new(
                1,
                "Ethernet",
            )
            .unwrap();

        adapter.set_mac([
            0x00,
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
        ]);

        assert!(adapter.has_mac());
    }

    #[test]
    fn metadata_table_stores_packets() {
        let mut table =
            MetadataTable::new();

        table.add_packet(
            PacketMetadata::new(
                1,
                100,
                100,
            )
            .unwrap(),
        );

        assert_eq!(
            table.packet_count(),
            1
        );
    }

    #[test]
    fn metadata_table_updates_adapter() {
        let mut table =
            MetadataTable::new();

        table.add_adapter(
            AdapterMetadata::new(
                1,
                "Ethernet",
            )
            .unwrap(),
        );

        table.add_adapter(
            AdapterMetadata::new(
                1,
                "Updated Ethernet",
            )
            .unwrap(),
        );

        assert_eq!(
            table.adapter_count(),
            1
        );

        assert_eq!(
            table.adapters()[0].name,
            "Updated Ethernet"
        );
    }
}