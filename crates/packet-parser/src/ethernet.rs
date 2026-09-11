#![forbid(unsafe_code)]

use network_core::error::EngineError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum EtherType {
    Ipv4 = 0x0800,
    Arp = 0x0806,
    Ipv6 = 0x86dd,
    Vlan = 0x8100,
    QinQ = 0x88a8,
    QinQLegacy = 0x9100,
    Unknown = 0xffff,
}

impl EtherType {
    pub fn from_u16(value: u16) -> Self {
        match value {
            0x0800 => Self::Ipv4,
            0x0806 => Self::Arp,
            0x86dd => Self::Ipv6,
            0x8100 => Self::Vlan,
            0x88a8 => Self::QinQ,
            0x9100 => Self::QinQLegacy,
            _ => Self::Unknown,
        }
    }

    pub fn is_vlan(self) -> bool {
        matches!(
            self,
            Self::Vlan | Self::QinQ | Self::QinQLegacy
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthernetHeader {
    pub destination: [u8; 6],
    pub source: [u8; 6],
    pub ether_type: EtherType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VlanHeader {
    pub tci: u16,
    pub ether_type: EtherType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetParseResult {
    pub header: EthernetHeader,
    pub vlan_tags: Vec<VlanHeader>,
    pub payload_offset: usize,
    pub payload_length: usize,
}

impl EthernetParseResult {
    pub fn payload<'a>(
        &self,
        packet: &'a [u8],
    ) -> &'a [u8] {
        let end = self
            .payload_offset
            .saturating_add(self.payload_length)
            .min(packet.len());

        if self.payload_offset >= end {
            return &[];
        }

        &packet[self.payload_offset..end]
    }
}

pub fn parse(
    packet: &[u8],
) -> Result<EthernetParseResult, EngineError> {
    if packet.len() < 14 {
        return Err(EngineError::packet_too_short());
    }

    let destination = [
        packet[0],
        packet[1],
        packet[2],
        packet[3],
        packet[4],
        packet[5],
    ];

    let source = [
        packet[6],
        packet[7],
        packet[8],
        packet[9],
        packet[10],
        packet[11],
    ];

    let mut ether_type = EtherType::from_u16(
        u16::from_be_bytes([packet[12], packet[13]]),
    );

    let mut offset = 14usize;
    let mut vlan_tags = Vec::new();

    /*
     * Ethernet permits stacked VLAN headers.
     *
     * Limit the number of tags to prevent malformed input
     * from creating an unbounded parsing loop.
     */
    while ether_type.is_vlan() {
        if vlan_tags.len() >= 4 {
            return Err(EngineError::packet_malformed());
        }

        if packet.len() < offset + 4 {
            return Err(EngineError::packet_too_short());
        }

        let tci =
            u16::from_be_bytes([
                packet[offset],
                packet[offset + 1],
            ]);

        let next_type =
            EtherType::from_u16(
                u16::from_be_bytes([
                    packet[offset + 2],
                    packet[offset + 3],
                ]),
            );

        vlan_tags.push(VlanHeader {
            tci,
            ether_type: next_type,
        });

        ether_type = next_type;
        offset += 4;
    }

    if offset > packet.len() {
        return Err(EngineError::packet_too_short());
    }

    Ok(EthernetParseResult {
        header: EthernetHeader {
            destination,
            source,
            ether_type,
        },
        vlan_tags,
        payload_offset: offset,
        payload_length: packet.len() - offset,
    })
}

pub fn ether_type(
    packet: &[u8],
) -> Result<EtherType, EngineError> {
    if packet.len() < 14 {
        return Err(EngineError::packet_too_short());
    }

    Ok(EtherType::from_u16(
        u16::from_be_bytes([
            packet[12],
            packet[13],
        ]),
    ))
}

pub fn is_vlan_frame(packet: &[u8]) -> bool {
    if packet.len() < 14 {
        return false;
    }

    EtherType::from_u16(
        u16::from_be_bytes([
            packet[12],
            packet[13],
        ]),
    )
    .is_vlan()
}

pub fn mac_is_broadcast(mac: &[u8; 6]) -> bool {
    *mac == [0xff; 6]
}

pub fn mac_is_multicast(mac: &[u8; 6]) -> bool {
    (mac[0] & 0x01) != 0
}

pub fn mac_is_unicast(mac: &[u8; 6]) -> bool {
    !mac_is_multicast(mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ethernet_packet(
        ether_type: u16,
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 14 + 4];

        packet[0..6].copy_from_slice(
            &[0, 1, 2, 3, 4, 5],
        );

        packet[6..12].copy_from_slice(
            &[6, 7, 8, 9, 10, 11],
        );

        packet[12..14]
            .copy_from_slice(&ether_type.to_be_bytes());

        packet[14..18]
            .copy_from_slice(&[1, 2, 3, 4]);

        packet
    }

    #[test]
    fn parses_ipv4_ethernet() {
        let packet = ethernet_packet(0x0800);

        let result = parse(&packet).unwrap();

        assert_eq!(
            result.header.ether_type,
            EtherType::Ipv4
        );

        assert_eq!(result.payload_offset, 14);
        assert_eq!(result.payload_length, 4);
        assert!(result.vlan_tags.is_empty());
    }

    #[test]
    fn parses_vlan() {
        let mut packet = vec![0u8; 18];

        packet[12] = 0x81;
        packet[13] = 0x00;

        packet[14] = 0x00;
        packet[15] = 0x64;

        packet[16] = 0x08;
        packet[17] = 0x00;

        let result = parse(&packet).unwrap();

        assert_eq!(
            result.header.ether_type,
            EtherType::Ipv4
        );

        assert_eq!(result.vlan_tags.len(), 1);
        assert_eq!(result.vlan_tags[0].tci, 100);
        assert_eq!(result.payload_offset, 18);
    }

    #[test]
    fn parses_qinq() {
        let mut packet = vec![0u8; 22];

        packet[12] = 0x88;
        packet[13] = 0xa8;

        packet[14] = 0;
        packet[15] = 1;
        packet[16] = 0x81;
        packet[17] = 0;

        packet[18] = 0;
        packet[19] = 2;
        packet[20] = 0x08;
        packet[21] = 0;

        let result = parse(&packet).unwrap();

        assert_eq!(
            result.header.ether_type,
            EtherType::Ipv4
        );

        assert_eq!(result.vlan_tags.len(), 2);
        assert_eq!(result.payload_offset, 22);
    }

    #[test]
    fn rejects_short_frame() {
        let packet = [0u8; 13];

        assert_eq!(
            parse(&packet).unwrap_err(),
            EngineError::packet_too_short()
        );
    }

    #[test]
    fn rejects_too_many_vlan_tags() {
        let mut packet = vec![0u8; 14 + (4 * 5)];

        packet[12] = 0x81;
        packet[13] = 0x00;

        for index in 0..4 {
            let offset = 14 + (index * 4);

            packet[offset] = 0;
            packet[offset + 1] = index as u8;

            packet[offset + 2] = 0x81;
            packet[offset + 3] = 0x00;
        }

        let result = parse(&packet);

        assert!(result.is_err());
    }

    #[test]
    fn detects_broadcast() {
        assert!(mac_is_broadcast(&[0xff; 6]));
    }

    #[test]
    fn detects_multicast() {
        assert!(mac_is_multicast(
            &[0x01, 0, 0, 0, 0, 0]
        ));
    }

    #[test]
    fn detects_unicast() {
        assert!(mac_is_unicast(
            &[0x02, 0, 0, 0, 0, 0]
        ));
    }

    #[test]
    fn payload_returns_correct_slice() {
        let packet = ethernet_packet(0x0800);

        let result = parse(&packet).unwrap();

        assert_eq!(
            result.payload(&packet),
            &[1, 2, 3, 4]
        );
    }
}