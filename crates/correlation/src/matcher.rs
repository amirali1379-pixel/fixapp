use network_core::{FlowKey, PacketObservation, Protocol};
use packet_parser::{ParsedPacket, TransportProtocol};

#[derive(Debug, Clone, Copy, Default)]
pub struct ObservationMatcher;

impl ObservationMatcher {
    pub fn to_flow_key(obs: &PacketObservation) -> Option<FlowKey> {
        let parsed = ParsedPacket::parse(obs).ok()?;

        let src_ip = parsed.source_ip?;
        let dst_ip = parsed.destination_ip?;

        let (protocol, src_port, dst_port) = match parsed.transport {
            TransportProtocol::Tcp => (
                Protocol::Tcp,
                parsed.source_port?,
                parsed.destination_port?,
            ),
            TransportProtocol::Udp => (
                Protocol::Udp,
                parsed.source_port?,
                parsed.destination_port?,
            ),
            TransportProtocol::Icmp => (
                Protocol::Icmp,
                0,
                0,
            ),
            TransportProtocol::Icmpv6 => (
                Protocol::IcmpV6,
                0,
                0,
            ),
            // A flow identity must never be fabricated from an unknown
            // transport protocol. In particular, port 0 is not a substitute
            // for missing TCP/UDP header data (e.g. non-first fragments).
            TransportProtocol::Unknown => return None,
        };

        Some(FlowKey {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        })
    }
}
