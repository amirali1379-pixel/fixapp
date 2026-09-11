#![forbid(unsafe_code)]

use std::net::Ipv6Addr;

use network_core::error::EngineError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Header {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Extension {
    pub header_type: u8,
    pub next_header: u8,
    pub offset: usize,
    pub length: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6ParseResult {
    pub header: Ipv6Header,
    pub header_offset: usize,
    pub transport_offset: usize,
    pub transport_length: usize,
    pub extensions: Vec<Ipv6Extension>,
    pub fragmented: bool,
    pub first_fragment: bool,
}

impl Ipv6ParseResult {
    pub fn transport_payload<'a>(
        &self,
        packet: &'a [u8],
    ) -> &'a [u8] {
        let end = self
            .transport_offset
            .saturating_add(self.transport_length)
            .min(packet.len());

        if self.transport_offset >= end {
            return &[];
        }

        &packet[self.transport_offset..end]
    }
}

pub fn parse(
    packet: &[u8],
) -> Result<Ipv6ParseResult, EngineError> {
    parse_at(packet, 0)
}

pub fn parse_at(
    packet: &[u8],
    offset: usize,
) -> Result<Ipv6ParseResult, EngineError> {
    if packet.len() < offset + 40 {
        return Err(EngineError::packet_too_short());
    }

    let first = packet[offset];

    if first >> 4 != 6 {
        return Err(EngineError::packet_malformed());
    }

    let traffic_class =
        ((first & 0x0f) << 4) |
        (packet[offset + 1] >> 4);

    let flow_label =
        ((packet[offset + 1] as u32 & 0x0f) << 16)
        | ((packet[offset + 2] as u32) << 8)
        | packet[offset + 3] as u32;

    let payload_length =
        u16::from_be_bytes([
            packet[offset + 4],
            packet[offset + 5],
        ]);

    let next_header = packet[offset + 6];
    let hop_limit = packet[offset + 7];

    let source = Ipv6Addr::from(
        <[u8; 16]>::try_from(
            &packet[offset + 8..offset + 24],
        )
        .map_err(|_| EngineError::packet_malformed())?,
    );

    let destination = Ipv6Addr::from(
        <[u8; 16]>::try_from(
            &packet[offset + 24..offset + 40],
        )
        .map_err(|_| EngineError::packet_malformed())?,
    );

    let payload_start = offset + 40;

    let payload_end = payload_start
        .checked_add(payload_length as usize)
        .ok_or_else(EngineError::integer_overflow)?;

    if packet.len() < payload_end {
        return Err(EngineError::packet_too_short());
    }

    let mut current_offset = payload_start;
    let mut current_header = next_header;

    let mut extensions = Vec::new();
    let mut fragmented = false;
    let mut first_fragment = true;

    for _ in 0..16 {
        match current_header {
            0 | 43 | 60 => {
                if current_offset + 2 > payload_end {
                    return Err(EngineError::packet_too_short());
                }

                let next = packet[current_offset];
                let hdr_ext_len = packet[current_offset + 1] as usize;
                let length = hdr_ext_len
                    .checked_add(1)
                    .and_then(|v| v.checked_mul(8))
                    .ok_or_else(EngineError::integer_overflow)?;
                let end = current_offset
                    .checked_add(length)
                    .ok_or_else(EngineError::integer_overflow)?;

                if end > payload_end {
                    return Err(EngineError::packet_too_short());
                }

                extensions.push(Ipv6Extension {
                    header_type: current_header,
                    next_header: next,
                    offset: current_offset,
                    length,
                });

                current_offset = end;
                current_header = next;
            }
            44 => {
                if current_offset + 8 > payload_end {
                    return Err(EngineError::packet_too_short());
                }

                let next = packet[current_offset];
                let fragment_field = u16::from_be_bytes([
                    packet[current_offset + 2],
                    packet[current_offset + 3],
                ]);
                let fragment_offset = (fragment_field >> 3) & 0x1fff;

                fragmented = true;
                first_fragment = fragment_offset == 0;

                extensions.push(Ipv6Extension {
                    header_type: 44,
                    next_header: next,
                    offset: current_offset,
                    length: 8,
                });

                current_offset += 8;
                current_header = next;

                if !first_fragment {
                    break;
                }
            }
            51 => {
                if current_offset + 2 > payload_end {
                    return Err(EngineError::packet_too_short());
                }

                let next = packet[current_offset];
                let payload_len = packet[current_offset + 1] as usize;
                let length = payload_len
                    .checked_add(2)
                    .and_then(|v| v.checked_mul(4))
                    .ok_or_else(EngineError::integer_overflow)?;
                let end = current_offset
                    .checked_add(length)
                    .ok_or_else(EngineError::integer_overflow)?;

                if end > payload_end {
                    return Err(EngineError::packet_too_short());
                }

                extensions.push(Ipv6Extension {
                    header_type: 51,
                    next_header: next,
                    offset: current_offset,
                    length,
                });

                current_offset = end;
                current_header = next;
            }
            50 => {
                return Ok(Ipv6ParseResult {
                    header: Ipv6Header {
                        version: 6,
                        traffic_class,
                        flow_label,
                        payload_length,
                        next_header,
                        hop_limit,
                        source,
                        destination,
                    },
                    header_offset: offset,
                    transport_offset: current_offset,
                    transport_length: payload_end.saturating_sub(current_offset),
                    extensions,
                    fragmented,
                    first_fragment,
                });
            }
            59 => {
                return Ok(Ipv6ParseResult {
                    header: Ipv6Header {
                        version: 6,
                        traffic_class,
                        flow_label,
                        payload_length,
                        next_header,
                        hop_limit,
                        source,
                        destination,
                    },
                    header_offset: offset,
                    transport_offset: current_offset,
                    transport_length: payload_end.saturating_sub(current_offset),
                    extensions,
                    fragmented,
                    first_fragment,
                });
            }
            _ => break,
        }
    }

    Ok(Ipv6ParseResult {
        header: Ipv6Header {
            version: 6,
            traffic_class,
            flow_label,
            payload_length,
            next_header,
            hop_limit,
            source,
            destination,
        },
        header_offset: offset,
        transport_offset: current_offset,
        transport_length: payload_end.saturating_sub(current_offset),
        extensions,
        fragmented,
        first_fragment,
    })
}

pub fn next_header(
    packet: &[u8],
) -> Result<u8, EngineError> {
    Ok(parse(packet)?.header.next_header)
}

pub fn source(
    packet: &[u8],
) -> Result<Ipv6Addr, EngineError> {
    Ok(parse(packet)?.header.source)
}

pub fn destination(
    packet: &[u8],
) -> Result<Ipv6Addr, EngineError> {
    Ok(parse(packet)?.header.destination)
}

pub fn transport_protocol(
    packet: &[u8],
) -> Result<u8, EngineError> {
    let parsed = parse(packet)?;

    if parsed.transport_offset >= packet.len() {
        return Ok(59);
    }

    if let Some(extension) = parsed.extensions.last() {
        return Ok(extension.next_header);
    }

    Ok(parsed.header.next_header)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basic_ipv6() -> Vec<u8> {
        let mut packet = vec![0u8; 40 + 8];
        packet[0] = 0x60;
        packet[4] = 0;
        packet[5] = 8;
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&[0x20,0x01,0xdb,0x08,0,0,0,0,0,0,0,0,0,0,0,1]);
        packet[24..40].copy_from_slice(&[0x20,0x01,0xdb,0x08,0,0,0,0,0,0,0,0,0,0,0,0]);
        packet[40] = 0x12;
        packet[41] = 0x34;
        packet[42] = 0;
        packet[43] = 0x35;
        packet
    }

    #[test]
    fn parses_basic_ipv6() {
        let packet = basic_ipv6();
        let result = parse(&packet).unwrap();
        assert_eq!(result.header.version, 6);
        assert_eq!(result.header.next_header, 17);
        assert_eq!(result.header.hop_limit, 64);
        assert_eq!(result.header.source, "2001:db08::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(result.header.destination, "2001:db08::".parse::<Ipv6Addr>().unwrap());
        assert_eq!(result.transport_offset, 40);
    }

    #[test]
    fn rejects_short_packet() { assert_eq!(parse(&[0u8;39]).unwrap_err(), EngineError::packet_too_short()); }

    #[test]
    fn rejects_wrong_version() { let mut packet=basic_ipv6(); packet[0]=0x40; assert!(parse(&packet).is_err()); }

    #[test]
    fn parses_hop_by_hop_extension() { let mut packet=vec![0u8;56]; packet[0]=0x60; packet[4]=0; packet[5]=16; packet[6]=0; packet[7]=64; packet[40]=17; packet[41]=0; let result=parse(&packet).unwrap(); assert_eq!(result.extensions.len(),1); assert_eq!(result.extensions[0].header_type,0); assert_eq!(result.extensions[0].next_header,17); assert_eq!(result.transport_offset,48); }

    #[test]
    fn parses_fragment_header() { let mut packet=vec![0u8;56]; packet[0]=0x60; packet[4]=0; packet[5]=16; packet[6]=44; packet[7]=64; packet[40]=17; packet[41]=0; let result=parse(&packet).unwrap(); assert!(result.fragmented); assert!(result.first_fragment); assert_eq!(result.extensions[0].header_type,44); }

    #[test]
    fn detects_non_first_fragment() { let mut packet=vec![0u8;48]; packet[0]=0x60; packet[4]=0; packet[5]=8; packet[6]=44; packet[7]=64; packet[40]=17; packet[42]=0; packet[43]=8; let result=parse(&packet).unwrap(); assert!(result.fragmented); assert!(!result.first_fragment); }

    #[test]
    fn parses_authentication_header() { let mut packet=vec![0u8;52]; packet[0]=0x60; packet[4]=0; packet[5]=12; packet[6]=51; packet[7]=64; packet[40]=17; packet[41]=1; let result=parse(&packet).unwrap(); assert_eq!(result.extensions.len(),1); assert_eq!(result.extensions[0].header_type,51); assert_eq!(result.transport_offset,52); }

    #[test]
    fn handles_no_next_header() { let mut packet=vec![0u8;40]; packet[0]=0x60; packet[6]=59; packet[7]=64; let result=parse(&packet).unwrap(); assert_eq!(result.header.next_header,59); assert_eq!(result.transport_length,0); }

    #[test]
    fn handles_esp_without_fabricating_transport() { let mut packet=vec![0u8;48]; packet[0]=0x60; packet[4]=0; packet[5]=8; packet[6]=50; packet[7]=64; let result=parse(&packet).unwrap(); assert_eq!(result.header.next_header,50); assert_eq!(result.transport_offset,40); assert_eq!(result.transport_length,8); }

    #[test]
    fn helper_functions_work() { let packet=basic_ipv6(); assert_eq!(next_header(&packet).unwrap(),17); assert_eq!(source(&packet).unwrap(),"2001:db08::1".parse::<Ipv6Addr>().unwrap()); assert_eq!(destination(&packet).unwrap(),"2001:db08::".parse::<Ipv6Addr>().unwrap()); }
}
