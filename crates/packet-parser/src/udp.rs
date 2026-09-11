#![forbid(unsafe_code)]

use network_core::error::EngineError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl UdpHeader {
    pub const SIZE: usize = 8;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpParseResult {
    pub header: UdpHeader,
    pub header_offset: usize,
    pub payload_offset: usize,
    pub payload_length: usize,
}

impl UdpParseResult {
    pub fn payload<'a>(&self, packet: &'a [u8]) -> &'a [u8] {
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

pub fn parse(packet: &[u8]) -> Result<UdpParseResult, EngineError> {
    parse_at(packet, 0)
}

pub fn parse_at(
    packet: &[u8],
    offset: usize,
) -> Result<UdpParseResult, EngineError> {
    let available = packet
        .len()
        .checked_sub(offset)
        .ok_or_else(EngineError::packet_too_short)?;

    parse_at_with_length(packet, offset, available)
}

pub fn parse_at_with_length(
    packet: &[u8],
    offset: usize,
    available_length: usize,
) -> Result<UdpParseResult, EngineError> {
    if available_length < UdpHeader::SIZE {
        return Err(EngineError::packet_too_short());
    }

    let end = offset
        .checked_add(available_length)
        .ok_or_else(EngineError::integer_overflow)?;

    if end > packet.len() {
        return Err(EngineError::packet_too_short());
    }

    let source_port = u16::from_be_bytes([
        packet[offset],
        packet[offset + 1],
    ]);

    let destination_port = u16::from_be_bytes([
        packet[offset + 2],
        packet[offset + 3],
    ]);

    let length = u16::from_be_bytes([
        packet[offset + 4],
        packet[offset + 5],
    ]);

    let checksum = u16::from_be_bytes([
        packet[offset + 6],
        packet[offset + 7],
    ]);

    if length < UdpHeader::SIZE as u16 {
        return Err(EngineError::packet_malformed());
    }

    let udp_length = usize::from(length);

    if udp_length > available_length {
        return Err(EngineError::packet_malformed());
    }

    let payload_offset = offset + UdpHeader::SIZE;
    let payload_length = udp_length - UdpHeader::SIZE;

    Ok(UdpParseResult {
        header: UdpHeader {
            source_port,
            destination_port,
            length,
            checksum,
        },
        header_offset: offset,
        payload_offset,
        payload_length,
    })
}

pub fn source_port(
    packet: &[u8],
) -> Result<u16, EngineError> {
    Ok(parse(packet)?.header.source_port)
}

pub fn destination_port(
    packet: &[u8],
) -> Result<u16, EngineError> {
    Ok(parse(packet)?.header.destination_port)
}

pub fn length(
    packet: &[u8],
) -> Result<u16, EngineError> {
    Ok(parse(packet)?.header.length)
}

pub fn checksum(
    packet: &[u8],
) -> Result<u16, EngineError> {
    Ok(parse(packet)?.header.checksum)
}

pub fn is_dns(
    packet: &[u8],
) -> Result<bool, EngineError> {
    let parsed = parse(packet)?;

    Ok(
        parsed.header.source_port == 53
            || parsed.header.destination_port == 53,
    )
}

pub fn is_dhcp(
    packet: &[u8],
) -> Result<bool, EngineError> {
    let parsed = parse(packet)?;

    let source = parsed.header.source_port;
    let destination = parsed.header.destination_port;

    Ok(
        (source == 67 && destination == 68)
            || (source == 68 && destination == 67),
    )
}

pub fn validate_checksum_ipv4(
    packet: &[u8],
    source: std::net::Ipv4Addr,
    destination: std::net::Ipv4Addr,
) -> Result<bool, EngineError> {
    let parsed = parse(packet)?;

    let udp_start = parsed.header_offset;

    let udp_end = parsed
        .payload_offset
        .checked_add(parsed.payload_length)
        .ok_or_else(EngineError::integer_overflow)?;

    let udp = &packet[udp_start..udp_end];

    let udp_length = u16::try_from(udp.len())
        .map_err(|_| EngineError::packet_malformed())?;

    let mut sum = 0u32;

    for octet_pair in source.octets().chunks_exact(2) {
        sum += u16::from_be_bytes([
            octet_pair[0],
            octet_pair[1],
        ]) as u32;
    }

    for octet_pair in destination.octets().chunks_exact(2) {
        sum += u16::from_be_bytes([
            octet_pair[0],
            octet_pair[1],
        ]) as u32;
    }

    // IPv4 pseudo-header:
    // zero + protocol(17) + UDP length
    sum += 17u32;
    sum += u32::from(udp_length);

    let mut index = 0;

    while index + 1 < udp.len() {
        let value = u16::from_be_bytes([
            udp[index],
            udp[index + 1],
        ]);

        sum += u32::from(value);
        index += 2;
    }

    if index < udp.len() {
        sum += u32::from(udp[index]) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // IPv4 UDP checksum value 0 means checksum
    // verification is intentionally disabled.
    if parsed.header.checksum == 0 {
        return Ok(true);
    }

    Ok((sum as u16) == 0xffff)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udp_packet() -> Vec<u8> {
        let mut packet = vec![0u8; 12];

        // Source port: 12345
        packet[0] = 0x30;
        packet[1] = 0x39;

        // Destination port: 53
        packet[2] = 0x00;
        packet[3] = 0x35;

        // UDP length: 12
        packet[4] = 0x00;
        packet[5] = 0x0c;

        // Checksum
        packet[6] = 0x12;
        packet[7] = 0x34;

        // Payload
        packet[8] = 1;
        packet[9] = 2;
        packet[10] = 3;
        packet[11] = 4;

        packet
    }

    #[test]
    fn parses_udp_header() {
        let packet = udp_packet();

        let result = parse(&packet).unwrap();

        assert_eq!(result.header.source_port, 12345);
        assert_eq!(result.header.destination_port, 53);
        assert_eq!(result.header.length, 12);
        assert_eq!(result.header.checksum, 0x1234);

        assert_eq!(result.payload_length, 4);
        assert_eq!(result.payload(&packet), &[1, 2, 3, 4]);
    }

    #[test]
    fn helper_functions_work() {
        let packet = udp_packet();

        assert_eq!(
            source_port(&packet).unwrap(),
            12345
        );

        assert_eq!(
            destination_port(&packet).unwrap(),
            53
        );

        assert_eq!(
            length(&packet).unwrap(),
            12
        );

        assert_eq!(
            checksum(&packet).unwrap(),
            0x1234
        );

        assert!(is_dns(&packet).unwrap());
        assert!(!is_dhcp(&packet).unwrap());
    }

    #[test]
    fn rejects_short_packet() {
        let packet = [0u8; 7];

        assert_eq!(
            parse(&packet).unwrap_err(),
            EngineError::packet_too_short()
        );
    }

    #[test]
    fn rejects_invalid_udp_length() {
        let mut packet = udp_packet();

        // UDP length smaller than header.
        packet[4] = 0;
        packet[5] = 7;

        assert!(parse(&packet).is_err());
    }

    #[test]
    fn rejects_length_larger_than_available_data() {
        let mut packet = udp_packet();

        // Advertise 100 bytes while only 12 exist.
        packet[4] = 0;
        packet[5] = 100;

        assert!(parse(&packet).is_err());
    }

    #[test]
    fn detects_dhcp() {
        let mut packet = udp_packet();

        // 67 -> 68
        packet[0] = 0;
        packet[1] = 67;
        packet[2] = 0;
        packet[3] = 68;

        assert!(is_dhcp(&packet).unwrap());
    }

    #[test]
    fn detects_dns_by_source_port() {
        let mut packet = udp_packet();

        // 53 -> 50000
        packet[0] = 0;
        packet[1] = 53;
        packet[2] = 0xc3;
        packet[3] = 0x50;

        assert!(is_dns(&packet).unwrap());
    }

    #[test]
    fn parses_at_offset() {
        let mut packet = vec![0u8; 20];

        packet[4] = 0x12;
        packet[5] = 0x34;

        packet[6] = 0x56;
        packet[7] = 0x78;

        packet[8] = 0;
        packet[9] = 8;

        let result = parse_at(
            &packet,
            4,
        ).unwrap();

        assert_eq!(
            result.header.source_port,
            0x1234
        );

        assert_eq!(
            result.header.destination_port,
            0x5678
        );

        assert_eq!(
            result.payload_length,
            0
        );
    }

    #[test]
    fn zero_checksum_is_accepted_for_ipv4() {
        let mut packet = udp_packet();

        packet[6] = 0;
        packet[7] = 0;

        let valid = validate_checksum_ipv4(
            &packet,
            std::net::Ipv4Addr::new(192, 168, 1, 10),
            std::net::Ipv4Addr::new(8, 8, 8, 8),
        ).unwrap();

        assert!(valid);
    }
}