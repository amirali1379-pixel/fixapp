#![forbid(unsafe_code)]

use std::net::Ipv4Addr;

use network_core::error::EngineError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Header {
    pub version: u8,
    pub ihl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
}

impl Ipv4Header {
    pub fn header_length(&self) -> usize {
        self.ihl as usize * 4
    }

    pub fn is_fragmented(&self) -> bool {
        self.more_fragments || self.fragment_offset != 0
    }

    pub fn is_first_fragment(&self) -> bool {
        self.fragment_offset == 0
    }

    pub fn payload_length(&self) -> usize {
        (self.total_length as usize)
            .saturating_sub(self.header_length())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4ParseResult {
    pub header: Ipv4Header,
    pub header_offset: usize,
    pub payload_offset: usize,
    pub payload_length: usize,
}

impl Ipv4ParseResult {
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
) -> Result<Ipv4ParseResult, EngineError> {
    parse_at(packet, 0)
}

pub fn parse_at(
    packet: &[u8],
    offset: usize,
) -> Result<Ipv4ParseResult, EngineError> {
    if packet.len() < offset + 20 {
        return Err(EngineError::packet_too_short());
    }

    let first = packet[offset];

    let version = first >> 4;
    let ihl = first & 0x0f;

    if version != 4 {
        return Err(EngineError::packet_malformed());
    }

    if ihl < 5 {
        return Err(EngineError::packet_malformed());
    }

    let header_length = (ihl as usize)
        .checked_mul(4)
        .ok_or_else(EngineError::integer_overflow)?;

    if packet.len() < offset + header_length {
        return Err(EngineError::packet_too_short());
    }

    let dscp = packet[offset + 1] >> 2;
    let ecn = packet[offset + 1] & 0x03;

    let total_length = u16::from_be_bytes([
        packet[offset + 2],
        packet[offset + 3],
    ]);

    if (total_length as usize) < header_length {
        return Err(EngineError::packet_malformed());
    }

    let total_end = offset
        .checked_add(total_length as usize)
        .ok_or_else(EngineError::integer_overflow)?;

    if packet.len() < total_end {
        return Err(EngineError::packet_too_short());
    }

    let identification =
        u16::from_be_bytes([
            packet[offset + 4],
            packet[offset + 5],
        ]);

    let flags_fragment =
        u16::from_be_bytes([
            packet[offset + 6],
            packet[offset + 7],
        ]);

    let dont_fragment =
        (flags_fragment & 0x4000) != 0;

    let more_fragments =
        (flags_fragment & 0x2000) != 0;

    let fragment_offset =
        flags_fragment & 0x1fff;

    let ttl = packet[offset + 8];
    let protocol = packet[offset + 9];

    let checksum =
        u16::from_be_bytes([
            packet[offset + 10],
            packet[offset + 11],
        ]);

    let source = Ipv4Addr::new(
        packet[offset + 12],
        packet[offset + 13],
        packet[offset + 14],
        packet[offset + 15],
    );

    let destination = Ipv4Addr::new(
        packet[offset + 16],
        packet[offset + 17],
        packet[offset + 18],
        packet[offset + 19],
    );

    let payload_offset = offset + header_length;
    let payload_length =
        total_length as usize - header_length;

    Ok(Ipv4ParseResult {
        header: Ipv4Header {
            version,
            ihl,
            dscp,
            ecn,
            total_length,
            identification,
            dont_fragment,
            more_fragments,
            fragment_offset,
            ttl,
            protocol,
            checksum,
            source,
            destination,
        },
        header_offset: offset,
        payload_offset,
        payload_length,
    })
}

pub fn protocol(
    packet: &[u8],
) -> Result<u8, EngineError> {
    Ok(parse(packet)?.header.protocol)
}

pub fn source(
    packet: &[u8],
) -> Result<Ipv4Addr, EngineError> {
    Ok(parse(packet)?.header.source)
}

pub fn destination(
    packet: &[u8],
) -> Result<Ipv4Addr, EngineError> {
    Ok(parse(packet)?.header.destination)
}

pub fn validate_checksum(
    packet: &[u8],
) -> Result<bool, EngineError> {
    let parsed = parse(packet)?;

    let start = parsed.header_offset;
    let end = start + parsed.header.header_length();

    let header = &packet[start..end];

    let mut sum = 0u32;

    let mut index = 0usize;

    while index < header.len() {
        let word = if index + 1 < header.len() {
            u16::from_be_bytes([
                header[index],
                header[index + 1],
            ])
        } else {
            (header[index] as u16) << 8
        };

        sum += word as u32;
        index += 2;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    Ok((sum as u16) == 0xffff)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet() -> Vec<u8> {
        let mut data = vec![0u8; 20 + 4];

        data[0] = 0x45;
        data[1] = 0;

        data[2] = 0;
        data[3] = 24;

        data[4] = 0x12;
        data[5] = 0x34;

        data[6] = 0x40;
        data[7] = 0;

        data[8] = 64;
        data[9] = 6;

        data[12] = 192;
        data[13] = 168;
        data[14] = 1;
        data[15] = 10;

        data[16] = 8;
        data[17] = 8;
        data[18] = 8;
        data[19] = 8;

        data[20..24]
            .copy_from_slice(&[1, 2, 3, 4]);

        data
    }

    #[test]
    fn parses_basic_ipv4() {
        let result = parse(&packet()).unwrap();

        assert_eq!(result.header.version, 4);
        assert_eq!(result.header.ihl, 5);
        assert_eq!(result.header.ttl, 64);
        assert_eq!(result.header.protocol, 6);

        assert_eq!(
            result.header.source,
            Ipv4Addr::new(192, 168, 1, 10)
        );

        assert_eq!(
            result.header.destination,
            Ipv4Addr::new(8, 8, 8, 8)
        );

        assert_eq!(
            result.payload(&packet()),
            &[1, 2, 3, 4]
        );
    }

    #[test]
    fn rejects_wrong_version() {
        let mut data = packet();
        data[0] = 0x65;

        assert!(parse(&data).is_err());
    }

    #[test]
    fn rejects_small_ihl() {
        let mut data = packet();
        data[0] = 0x44;

        assert!(parse(&data).is_err());
    }

    #[test]
    fn rejects_short_packet() {
        let data = [0u8; 19];

        assert_eq!(
            parse(&data).unwrap_err(),
            EngineError::packet_too_short()
        );
    }

    #[test]
    fn detects_fragmentation() {
        let mut data = packet();

        data[6] = 0x20;
        data[7] = 0;

        let result = parse(&data).unwrap();

        assert!(result.header.more_fragments);
        assert!(result.header.is_fragmented());
        assert!(result.header.is_first_fragment());
    }

    #[test]
    fn detects_non_first_fragment() {
        let mut data = packet();

        data[6] = 0;
        data[7] = 8;

        let result = parse(&data).unwrap();

        assert_eq!(
            result.header.fragment_offset,
            8
        );

        assert!(result.header.is_fragmented());
        assert!(!result.header.is_first_fragment());
    }

    #[test]
    fn parses_options() {
        let mut data = vec![0u8; 24];

        data[0] = 0x46;

        data[2] = 0;
        data[3] = 24;

        data[8] = 64;
        data[9] = 17;

        data[12..16]
            .copy_from_slice(
                &[10, 0, 0, 1]
            );

        data[16..20]
            .copy_from_slice(
                &[10, 0, 0, 2]
            );

        let result = parse(&data).unwrap();

        assert_eq!(
            result.header.header_length(),
            24
        );

        assert_eq!(result.payload_length, 0);
    }

    #[test]
    fn rejects_invalid_total_length() {
        let mut data = packet();

        data[2] = 0;
        data[3] = 10;

        assert!(parse(&data).is_err());
    }

    #[test]
    fn helper_functions_work() {
        let data = packet();

        assert_eq!(protocol(&data).unwrap(), 6);

        assert_eq!(
            source(&data).unwrap(),
            Ipv4Addr::new(192, 168, 1, 10)
        );

        assert_eq!(
            destination(&data).unwrap(),
            Ipv4Addr::new(8, 8, 8, 8)
        );
    }
}