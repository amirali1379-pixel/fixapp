#![forbid(unsafe_code)]

use network_core::error::EngineError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub data_offset: u8,
    pub reserved: u8,
    pub flags: u16,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
}

impl TcpHeader {
    pub fn header_length(&self) -> usize {
        self.data_offset as usize * 4
    }

    pub fn fin(&self) -> bool {
        self.flags & 0x001 != 0
    }

    pub fn syn(&self) -> bool {
        self.flags & 0x002 != 0
    }

    pub fn rst(&self) -> bool {
        self.flags & 0x004 != 0
    }

    pub fn psh(&self) -> bool {
        self.flags & 0x008 != 0
    }

    pub fn ack(&self) -> bool {
        self.flags & 0x010 != 0
    }

    pub fn urg(&self) -> bool {
        self.flags & 0x020 != 0
    }

    pub fn ece(&self) -> bool {
        self.flags & 0x040 != 0
    }

    pub fn cwr(&self) -> bool {
        self.flags & 0x080 != 0
    }

    pub fn ns(&self) -> bool {
        self.flags & 0x100 != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpParseResult {
    pub header: TcpHeader,
    pub header_offset: usize,
    pub payload_offset: usize,
    pub payload_length: usize,
}

impl TcpParseResult {
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
) -> Result<TcpParseResult, EngineError> {
    parse_at(packet, 0)
}

pub fn parse_at(
    packet: &[u8],
    offset: usize,
) -> Result<TcpParseResult, EngineError> {
    parse_at_with_length(
        packet,
        offset,
        packet.len().saturating_sub(offset),
    )
}

pub fn parse_at_with_length(
    packet: &[u8],
    offset: usize,
    length: usize,
) -> Result<TcpParseResult, EngineError> {
    if length < 20 {
        return Err(EngineError::packet_too_short());
    }

    let end = offset
        .checked_add(length)
        .ok_or_else(EngineError::integer_overflow)?;

    if packet.len() < end {
        return Err(EngineError::packet_too_short());
    }

    if packet.len() < offset + 20 {
        return Err(EngineError::packet_too_short());
    }

    let source_port =
        u16::from_be_bytes([
            packet[offset],
            packet[offset + 1],
        ]);

    let destination_port =
        u16::from_be_bytes([
            packet[offset + 2],
            packet[offset + 3],
        ]);

    let sequence_number =
        u32::from_be_bytes([
            packet[offset + 4],
            packet[offset + 5],
            packet[offset + 6],
            packet[offset + 7],
        ]);

    let acknowledgment_number =
        u32::from_be_bytes([
            packet[offset + 8],
            packet[offset + 9],
            packet[offset + 10],
            packet[offset + 11],
        ]);

    let data_offset =
        packet[offset + 12] >> 4;

    if data_offset < 5 {
        return Err(EngineError::packet_malformed());
    }

    let header_length = (data_offset as usize)
        .checked_mul(4)
        .ok_or_else(EngineError::integer_overflow)?;

    if header_length > length {
        return Err(EngineError::packet_malformed());
    }

    if packet.len() < offset + header_length {
        return Err(EngineError::packet_too_short());
    }

    let reserved =
        (packet[offset + 12] & 0x0e) >> 1;

    let ns =
        (packet[offset + 12] & 0x01) != 0;

    let flags =
        ((packet[offset + 13] as u16) & 0xff)
            | ((ns as u16) << 8);

    let window_size =
        u16::from_be_bytes([
            packet[offset + 14],
            packet[offset + 15],
        ]);

    let checksum =
        u16::from_be_bytes([
            packet[offset + 16],
            packet[offset + 17],
        ]);

    let urgent_pointer =
        u16::from_be_bytes([
            packet[offset + 18],
            packet[offset + 19],
        ]);

    let payload_offset = offset + header_length;
    let payload_length = length - header_length;

    Ok(TcpParseResult {
        header: TcpHeader {
            source_port,
            destination_port,
            sequence_number,
            acknowledgment_number,
            data_offset,
            reserved,
            flags,
            window_size,
            checksum,
            urgent_pointer,
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

pub fn flags(
    packet: &[u8],
) -> Result<u16, EngineError> {
    Ok(parse(packet)?.header.flags)
}

pub fn is_syn(
    packet: &[u8],
) -> Result<bool, EngineError> {
    Ok(parse(packet)?.header.syn())
}

pub fn is_ack(
    packet: &[u8],
) -> Result<bool, EngineError> {
    Ok(parse(packet)?.header.ack())
}

pub fn is_fin(
    packet: &[u8],
) -> Result<bool, EngineError> {
    Ok(parse(packet)?.header.fin())
}

pub fn is_rst(
    packet: &[u8],
) -> Result<bool, EngineError> {
    Ok(parse(packet)?.header.rst())
}

pub fn validate_checksum(
    packet: &[u8],
    source: std::net::Ipv4Addr,
    destination: std::net::Ipv4Addr,
) -> Result<bool, EngineError> {
    let parsed = parse(packet)?;

    let tcp_start = parsed.header_offset;
    let tcp_end = parsed
        .payload_offset
        .checked_add(parsed.payload_length)
        .ok_or_else(EngineError::integer_overflow)?;

    let tcp = &packet[tcp_start..tcp_end];

    let mut pseudo = Vec::with_capacity(
        12usize
            .checked_add(tcp.len())
            .ok_or_else(EngineError::integer_overflow)?,
    );

    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());

    pseudo.push(0);
    pseudo.push(6);

    let tcp_length =
        u16::try_from(tcp.len())
            .map_err(|_| EngineError::packet_malformed())?;

    pseudo.extend_from_slice(
        &tcp_length.to_be_bytes(),
    );

    pseudo.extend_from_slice(tcp);

    if pseudo.len() % 2 != 0 {
        pseudo.push(0);
    }

    let mut sum = 0u32;

    for chunk in pseudo.chunks_exact(2) {
        sum += u16::from_be_bytes([
            chunk[0],
            chunk[1],
        ]) as u32;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    Ok((sum as u16) == 0xffff)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_packet() -> Vec<u8> {
        let mut packet = vec![0u8; 24];

        packet[0] = 0x04;
        packet[1] = 0xd2;

        packet[2] = 0x00;
        packet[3] = 0x50;

        packet[4] = 0x12;
        packet[5] = 0x34;
        packet[6] = 0x56;
        packet[7] = 0x78;

        packet[8] = 0x87;
        packet[9] = 0x65;
        packet[10] = 0x43;
        packet[11] = 0x21;

        packet[12] = 0x50;
        packet[13] = 0x18;

        packet[14] = 0x10;
        packet[15] = 0x00;

        packet[16] = 0;
        packet[17] = 0;

        packet[18] = 0;
        packet[19] = 0;

        packet[20..24]
            .copy_from_slice(&[1, 2, 3, 4]);

        packet
    }

    #[test]
    fn parses_tcp_header() {
        let packet = tcp_packet();

        let result = parse(&packet).unwrap();

        assert_eq!(
            result.header.source_port,
            1234
        );

        assert_eq!(
            result.header.destination_port,
            80
        );

        assert_eq!(
            result.header.sequence_number,
            0x12345678
        );

        assert_eq!(
            result.header.acknowledgment_number,
            0x87654321
        );

        assert_eq!(
            result.header.header_length(),
            20
        );

        assert_eq!(
            result.payload(&packet),
            &[1, 2, 3, 4]
        );
    }

    #[test]
    fn parses_flags() {
        let packet = tcp_packet();

        let result = parse(&packet).unwrap();

        assert!(result.header.psh());
        assert!(result.header.ack());
        assert!(!result.header.syn());
        assert!(!result.header.fin());
        assert!(!result.header.rst());
    }

    #[test]
    fn rejects_short_header() {
        let packet = [0u8; 19];

        assert_eq!(
            parse(&packet).unwrap_err(),
            EngineError::packet_too_short()
        );
    }

    #[test]
    fn rejects_invalid_data_offset() {
        let mut packet = tcp_packet();

        packet[12] = 0x40;

        assert!(parse(&packet).is_err());
    }

    #[test]
    fn parses_tcp_options_length() {
        let mut packet = vec![0u8; 32];

        packet[0] = 0;
        packet[1] = 80;

        packet[2] = 1;
        packet[3] = 187;

        packet[12] = 0x80;

        let result = parse(&packet).unwrap();

        assert_eq!(
            result.header.header_length(),
            32
        );

        assert_eq!(result.payload_length, 0);
    }

    #[test]
    fn helper_functions_work() {
        let packet = tcp_packet();

        assert_eq!(
            source_port(&packet).unwrap(),
            1234
        );

        assert_eq!(
            destination_port(&packet).unwrap(),
            80
        );

        assert!(is_ack(&packet).unwrap());
        assert!(!is_syn(&packet).unwrap());
        assert!(!is_fin(&packet).unwrap());
        assert!(!is_rst(&packet).unwrap());
    }
}