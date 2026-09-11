#![forbid(unsafe_code)]

pub mod arp;
pub mod ethernet;
pub mod icmp;
pub mod icmpv6;
pub mod ipv4;
pub mod ipv6;
pub mod tcp;
pub mod udp;
pub mod vlan;

use network_core::{
    error::EngineError,
    observation::PacketObservation,
    BackendSource,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketInputLayer {
    Ethernet = 0,
    Ip = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkProtocol {
    Unknown,
    Arp,
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    Unknown,
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPacket {
    pub source: BackendSource,
    pub protocol: NetworkProtocol,
    pub transport: TransportProtocol,
    pub payload_offset: usize,
    pub payload_length: usize,
    pub source_ip: Option<std::net::IpAddr>,
    pub destination_ip: Option<std::net::IpAddr>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
}

impl ParsedPacket {
    pub fn parse(observation: &PacketObservation) -> Result<Self, EngineError> {
        Self::parse_bytes(
            observation.backend_source,
            observation.packet.as_slice(),
            PacketInputLayer::Ethernet,
        )
    }

    pub fn parse_ip(observation: &PacketObservation) -> Result<Self, EngineError> {
        Self::parse_bytes(
            observation.backend_source,
            observation.packet.as_slice(),
            PacketInputLayer::Ip,
        )
    }

    pub fn parse_bytes(
        source: BackendSource,
        raw: &[u8],
        layer: PacketInputLayer,
    ) -> Result<Self, EngineError> {
        if raw.is_empty() {
            return Err(EngineError::packet_too_short());
        }

        match layer {
            PacketInputLayer::Ethernet => Self::parse_ethernet(source, raw),
            PacketInputLayer::Ip => Self::parse_ip_layer(source, raw),
        }
    }

    fn parse_ethernet(source: BackendSource, raw: &[u8]) -> Result<Self, EngineError> {
        let ethernet = ethernet::parse(raw)?;
        let payload = ethernet.payload(raw);

        match ethernet.header.ether_type {
            ethernet::EtherType::Ipv4 => Self::parse_ipv4(source, raw, ethernet.payload_offset),
            ethernet::EtherType::Ipv6 => Self::parse_ipv6(source, raw, ethernet.payload_offset),
            ethernet::EtherType::Arp => {
                arp::parse_at(raw, ethernet.payload_offset)?;
                Ok(Self {
                    source,
                    protocol: NetworkProtocol::Arp,
                    transport: TransportProtocol::Unknown,
                    payload_offset: ethernet.payload_offset,
                    payload_length: payload.len(),
                    source_ip: None,
                    destination_ip: None,
                    source_port: None,
                    destination_port: None,
                })
            }
            _ => Err(EngineError::packet_unsupported()),
        }
    }

    fn parse_ip_layer(source: BackendSource, raw: &[u8]) -> Result<Self, EngineError> {
        match raw[0] >> 4 {
            4 => Self::parse_ipv4(source, raw, 0),
            6 => Self::parse_ipv6(source, raw, 0),
            _ => Err(EngineError::packet_unsupported()),
        }
    }

    fn parse_ipv4(
        source: BackendSource,
        raw: &[u8],
        offset: usize,
    ) -> Result<Self, EngineError> {
        let parsed = ipv4::parse_at(raw, offset)?;
        let header = parsed.header;
        let payload_offset = parsed.payload_offset;
        let payload_length = parsed.payload_length;

        let transport = match header.protocol {
            6 => TransportProtocol::Tcp,
            17 => TransportProtocol::Udp,
            1 => TransportProtocol::Icmp,
            _ => TransportProtocol::Unknown,
        };

        let (source_port, destination_port) = if header.fragment_offset != 0 {
            (None, None)
        } else {
            match transport {
                TransportProtocol::Tcp => {
                    if payload_length < 20 {
                        (None, None)
                    } else {
                        let tcp = tcp::parse_at_with_length(raw, payload_offset, payload_length)?;
                        (Some(tcp.header.source_port), Some(tcp.header.destination_port))
                    }
                }
                TransportProtocol::Udp => {
                    if payload_length < udp::UdpHeader::SIZE {
                        (None, None)
                    } else {
                        let udp = udp::parse_at_with_length(raw, payload_offset, payload_length)?;
                        (Some(udp.header.source_port), Some(udp.header.destination_port))
                    }
                }
                TransportProtocol::Icmp => {
                    if payload_length < icmp::IcmpPacket::HEADER_LEN {
                        (None, None)
                    } else {
                        icmp::IcmpPacket::parse(&raw[payload_offset..payload_offset + payload_length])
                            .ok_or_else(EngineError::packet_malformed)?;
                        (None, None)
                    }
                }
                _ => (None, None),
            }
        };

        Ok(Self {
            source,
            protocol: NetworkProtocol::Ipv4,
            transport,
            payload_offset,
            payload_length,
            source_ip: Some(std::net::IpAddr::V4(header.source)),
            destination_ip: Some(std::net::IpAddr::V4(header.destination)),
            source_port,
            destination_port,
        })
    }

    fn parse_ipv6(
        source: BackendSource,
        raw: &[u8],
        offset: usize,
    ) -> Result<Self, EngineError> {
        let parsed = ipv6::parse_at(raw, offset)?;
        let header = parsed.header;
        let payload_offset = parsed.transport_offset;
        let payload_length = parsed.transport_length;

        let next_header = parsed
            .extensions
            .last()
            .map(|extension| extension.next_header)
            .unwrap_or(header.next_header);

        let transport = match next_header {
            6 => TransportProtocol::Tcp,
            17 => TransportProtocol::Udp,
            58 => TransportProtocol::Icmpv6,
            _ => TransportProtocol::Unknown,
        };

        let (source_port, destination_port) = if !parsed.first_fragment && parsed.fragmented {
            (None, None)
        } else {
            match transport {
                TransportProtocol::Tcp => {
                    if payload_length < 20 {
                        (None, None)
                    } else {
                        let tcp = tcp::parse_at_with_length(raw, payload_offset, payload_length)?;
                        (Some(tcp.header.source_port), Some(tcp.header.destination_port))
                    }
                }
                TransportProtocol::Udp => {
                    if payload_length < udp::UdpHeader::SIZE {
                        (None, None)
                    } else {
                        let udp = udp::parse_at_with_length(raw, payload_offset, payload_length)?;
                        (Some(udp.header.source_port), Some(udp.header.destination_port))
                    }
                }
                TransportProtocol::Icmpv6 => {
                    if payload_length < icmpv6::IcmpV6Packet::HEADER_LEN {
                        (None, None)
                    } else {
                        icmpv6::IcmpV6Packet::parse(&raw[payload_offset..payload_offset + payload_length])
                            .ok_or_else(EngineError::packet_malformed)?;
                        (None, None)
                    }
                }
                _ => (None, None),
            }
        };

        Ok(Self {
            source,
            protocol: NetworkProtocol::Ipv6,
            transport,
            payload_offset,
            payload_length,
            source_ip: Some(std::net::IpAddr::V6(header.source)),
            destination_ip: Some(std::net::IpAddr::V6(header.destination)),
            source_port,
            destination_port,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modules_are_available_through_canonical_parser() {
        assert_eq!(vlan::VlanHeader::HEADER_LEN, 4);
        assert_eq!(icmp::IcmpPacket::HEADER_LEN, 8);
        assert_eq!(icmpv6::IcmpV6Packet::HEADER_LEN, 8);
    }
}
