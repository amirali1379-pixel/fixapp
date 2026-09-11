#![forbid(unsafe_code)]

use std::net::Ipv4Addr;

use network_core::error::EngineError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpHardwareType {
    Ethernet,
    Unknown(u16),
}

impl ArpHardwareType {
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => Self::Ethernet,
            other => Self::Unknown(other),
        }
    }

    pub fn as_u16(self) -> u16 {
        match self {
            Self::Ethernet => 1,
            Self::Unknown(value) => value,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpOperation {
    Request,
    Reply,
    Unknown(u16),
}

impl ArpOperation {
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => Self::Request,
            2 => Self::Reply,
            other => Self::Unknown(other),
        }
    }

    pub fn as_u16(self) -> u16 {
        match self {
            Self::Request => 1,
            Self::Reply => 2,
            Self::Unknown(value) => value,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpHeader {
    pub hardware_type: ArpHardwareType,
    pub protocol_type: u16,
    pub hardware_address_length: u8,
    pub protocol_address_length: u8,
    pub operation: ArpOperation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpPacket {
    pub header: ArpHeader,
    pub sender_hardware_address: [u8; 6],
    pub sender_protocol_address: Ipv4Addr,
    pub target_hardware_address: [u8; 6],
    pub target_protocol_address: Ipv4Addr,
}

impl ArpPacket {
    pub const ETHERNET_IPV4_SIZE: usize = 28;

    pub fn is_request(&self) -> bool {
        self.header.operation == ArpOperation::Request
    }

    pub fn is_reply(&self) -> bool {
        self.header.operation == ArpOperation::Reply
    }

    pub fn is_for_ipv4(&self, address: Ipv4Addr) -> bool {
        self.target_protocol_address == address
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpParseResult {
    pub packet: ArpPacket,
    pub header_offset: usize,
    pub packet_length: usize,
}

pub fn parse(packet: &[u8]) -> Result<ArpParseResult, EngineError> {
    parse_at(packet, 0)
}

pub fn parse_at(
    packet: &[u8],
    offset: usize,
) -> Result<ArpParseResult, EngineError> {
    let remaining = packet
        .len()
        .checked_sub(offset)
        .ok_or_else(EngineError::packet_too_short)?;

    if remaining < ArpPacket::ETHERNET_IPV4_SIZE {
        return Err(EngineError::packet_too_short());
    }

    let hardware_type = u16::from_be_bytes([
        packet[offset],
        packet[offset + 1],
    ]);

    let protocol_type = u16::from_be_bytes([
        packet[offset + 2],
        packet[offset + 3],
    ]);

    let hardware_address_length = packet[offset + 4];
    let protocol_address_length = packet[offset + 5];

    let operation = u16::from_be_bytes([
        packet[offset + 6],
        packet[offset + 7],
    ]);

    // This parser currently supports the standard
    // Ethernet + IPv4 ARP layout.
    if hardware_type != 1 {
        return Err(EngineError::packet_unsupported());
    }

    if protocol_type != 0x0800 {
        return Err(EngineError::packet_unsupported());
    }

    if hardware_address_length != 6 {
        return Err(EngineError::packet_malformed());
    }

    if protocol_address_length != 4 {
        return Err(EngineError::packet_malformed());
    }

    let sender_hardware_address = [
        packet[offset + 8],
        packet[offset + 9],
        packet[offset + 10],
        packet[offset + 11],
        packet[offset + 12],
        packet[offset + 13],
    ];

    let sender_protocol_address = Ipv4Addr::new(
        packet[offset + 14],
        packet[offset + 15],
        packet[offset + 16],
        packet[offset + 17],
    );

    let target_hardware_address = [
        packet[offset + 18],
        packet[offset + 19],
        packet[offset + 20],
        packet[offset + 21],
        packet[offset + 22],
        packet[offset + 23],
    ];

    let target_protocol_address = Ipv4Addr::new(
        packet[offset + 24],
        packet[offset + 25],
        packet[offset + 26],
        packet[offset + 27],
    );

    Ok(ArpParseResult {
        packet: ArpPacket {
            header: ArpHeader {
                hardware_type: ArpHardwareType::from_u16(
                    hardware_type,
                ),
                protocol_type,
                hardware_address_length,
                protocol_address_length,
                operation: ArpOperation::from_u16(operation),
            },
            sender_hardware_address,
            sender_protocol_address,
            target_hardware_address,
            target_protocol_address,
        },
        header_offset: offset,
        packet_length: ArpPacket::ETHERNET_IPV4_SIZE,
    })
}

pub fn is_arp_request(
    packet: &[u8],
) -> Result<bool, EngineError> {
    Ok(parse(packet)?.packet.is_request())
}

pub fn is_arp_reply(
    packet: &[u8],
) -> Result<bool, EngineError> {
    Ok(parse(packet)?.packet.is_reply())
}

pub fn sender_ip(
    packet: &[u8],
) -> Result<Ipv4Addr, EngineError> {
    Ok(parse(packet)?.packet.sender_protocol_address)
}

pub fn target_ip(
    packet: &[u8],
) -> Result<Ipv4Addr, EngineError> {
    Ok(parse(packet)?.packet.target_protocol_address)
}

pub fn sender_mac(
    packet: &[u8],
) -> Result<[u8; 6], EngineError> {
    Ok(parse(packet)?.packet.sender_hardware_address)
}

pub fn target_mac(
    packet: &[u8],
) -> Result<[u8; 6], EngineError> {
    Ok(parse(packet)?.packet.target_hardware_address)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arp_request() -> Vec<u8> {
        vec![
            // Hardware type: Ethernet
            0x00, 0x01,

            // Protocol type: IPv4
            0x08, 0x00,

            // Hardware address length
            0x06,

            // Protocol address length
            0x04,

            // Operation: request
            0x00, 0x01,

            // Sender MAC
            0xaa, 0xbb, 0xcc,
            0xdd, 0xee, 0xff,

            // Sender IP: 192.168.1.10
            192, 168, 1, 10,

            // Target MAC
            0x00, 0x00, 0x00,
            0x00, 0x00, 0x00,

            // Target IP: 192.168.1.1
            192, 168, 1, 1,
        ]
    }

    fn arp_reply() -> Vec<u8> {
        vec![
            // Hardware type
            0x00, 0x01,

            // Protocol type
            0x08, 0x00,

            // Hardware length
            0x06,

            // Protocol length
            0x04,

            // Operation: reply
            0x00, 0x02,

            // Sender MAC
            0x11, 0x22, 0x33,
            0x44, 0x55, 0x66,

            // Sender IP
            192, 168, 1, 1,

            // Target MAC
            0xaa, 0xbb, 0xcc,
            0xdd, 0xee, 0xff,

            // Target IP
            192, 168, 1, 10,
        ]
    }

    #[test]
    fn parses_arp_request() {
        let packet = arp_request();

        let result = parse(&packet).unwrap();

        assert_eq!(
            result.packet.header.hardware_type,
            ArpHardwareType::Ethernet
        );

        assert_eq!(
            result.packet.header.protocol_type,
            0x0800
        );

        assert_eq!(
            result.packet.header.operation,
            ArpOperation::Request
        );

        assert_eq!(
            result.packet.sender_protocol_address,
            Ipv4Addr::new(192, 168, 1, 10)
        );

        assert_eq!(
            result.packet.target_protocol_address,
            Ipv4Addr::new(192, 168, 1, 1)
        );

        assert!(result.packet.is_request());
        assert!(!result.packet.is_reply());
    }

    #[test]
    fn parses_arp_reply() {
        let packet = arp_reply();

        let result = parse(&packet).unwrap();

        assert_eq!(
            result.packet.header.operation,
            ArpOperation::Reply
        );

        assert!(result.packet.is_reply());
        assert!(!result.packet.is_request());
    }

    #[test]
    fn parses_mac_addresses() {
        let packet = arp_request();

        assert_eq!(
            sender_mac(&packet).unwrap(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );

        assert_eq!(
            target_mac(&packet).unwrap(),
            [0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn parses_ip_addresses() {
        let packet = arp_request();

        assert_eq!(
            sender_ip(&packet).unwrap(),
            Ipv4Addr::new(192, 168, 1, 10)
        );

        assert_eq!(
            target_ip(&packet).unwrap(),
            Ipv4Addr::new(192, 168, 1, 1)
        );
    }

    #[test]
    fn detects_request_and_reply() {
        let request = arp_request();
        let reply = arp_reply();

        assert!(is_arp_request(&request).unwrap());
        assert!(!is_arp_reply(&request).unwrap());

        assert!(is_arp_reply(&reply).unwrap());
        assert!(!is_arp_request(&reply).unwrap());
    }

    #[test]
    fn detects_target_ip() {
        let packet = arp_request();

        assert!(
            parse(&packet)
                .unwrap()
                .packet
                .is_for_ipv4(
                    Ipv4Addr::new(
                        192,
                        168,
                        1,
                        1
                    )
                )
        );
    }

    #[test]
    fn rejects_short_packet() {
        let packet = [0u8; 27];

        assert_eq!(
            parse(&packet).unwrap_err(),
            EngineError::packet_too_short()
        );
    }

    #[test]
    fn rejects_non_ethernet_arp() {
        let mut packet = arp_request();

        packet[1] = 0x02;

        assert_eq!(
            parse(&packet).unwrap_err(),
            EngineError::packet_unsupported()
        );
    }

    #[test]
    fn rejects_non_ipv4_protocol() {
        let mut packet = arp_request();

        packet[2] = 0x86;
        packet[3] = 0xdd;

        assert_eq!(
            parse(&packet).unwrap_err(),
            EngineError::packet_unsupported()
        );
    }

    #[test]
    fn rejects_invalid_hardware_length() {
        let mut packet = arp_request();

        packet[4] = 8;

        assert_eq!(
            parse(&packet).unwrap_err(),
            EngineError::packet_malformed()
        );
    }

    #[test]
    fn rejects_invalid_protocol_length() {
        let mut packet = arp_request();

        packet[5] = 16;

        assert_eq!(
            parse(&packet).unwrap_err(),
            EngineError::packet_malformed()
        );
    }

    #[test]
    fn parses_with_offset() {
        let arp = arp_request();

        let mut packet = vec![0u8; 14];
        packet.extend_from_slice(&arp);

        let result = parse_at(
            &packet,
            14,
        ).unwrap();

        assert_eq!(
            result.header_offset,
            14
        );

        assert_eq!(
            result.packet_length,
            28
        );

        assert_eq!(
            result.packet.sender_protocol_address,
            Ipv4Addr::new(192, 168, 1, 10)
        );
    }
}