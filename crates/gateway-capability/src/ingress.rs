use network_core::{
    observation::{ObservationId, PacketObservation},
    packet::Packet,
    timestamp::Timestamp,
    BackendSource, Direction,
};
use packet_parser::{NetworkProtocol, ParsedPacket, TransportProtocol};

use crate::{ConnectionKey, ConnectionProtocol, GatewayRuntime};

#[derive(Debug, PartialEq)]
pub struct IngressPacket {
    pub observation: PacketObservation,
    pub interface_id: u32,
    pub parsed: Option<ParsedPacket>,
    pub connection_key: Option<ConnectionKey>,
    pub connection_found: bool,
}

impl IngressPacket {
    pub fn new(
        observation: PacketObservation,
        interface_id: u32,
    ) -> Option<Self> {
        if interface_id == 0 {
            return None;
        }
        if observation.packet.is_empty() {
            return None;
        }
        Some(Self {
            observation,
            interface_id,
            parsed: None,
            connection_key: None,
            connection_found: false,
        })
    }

    pub fn packet_len(&self) -> usize {
        self.observation.packet.len()
    }

    pub fn interface_id(&self) -> u32 {
        self.interface_id
    }

    pub fn observation(&self) -> &PacketObservation {
        &self.observation
    }

    pub fn parsed(&self) -> Option<&ParsedPacket> {
        self.parsed.as_ref()
    }

    pub fn connection_key(&self) -> Option<&ConnectionKey> {
        self.connection_key.as_ref()
    }

    pub fn connection_found(&self) -> bool {
        self.connection_found
    }

    pub fn into_observation(self) -> PacketObservation {
        self.observation
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressError {
    InvalidInterface,
    EmptyPacket,
    ParseFailed,
}

#[derive(Debug, Default)]
pub struct IngressProcessor;

impl IngressProcessor {
    pub fn new() -> Self {
        Self
    }

    pub fn accept(
        &self,
        observation: PacketObservation,
        interface_id: u32,
    ) -> Result<IngressPacket, IngressError> {
        if interface_id == 0 {
            return Err(IngressError::InvalidInterface);
        }
        if observation.packet.is_empty() {
            return Err(IngressError::EmptyPacket);
        }

        let mut packet = IngressPacket::new(observation, interface_id)
            .ok_or(IngressError::InvalidInterface)?;
        let parsed = ParsedPacket::parse(&packet.observation)
            .map_err(|_| IngressError::ParseFailed)?;
        packet.connection_key = connection_key_from_parsed(&parsed);
        packet.parsed = Some(parsed);
        Ok(packet)
    }

    pub fn accept_into_runtime(
        &self,
        observation: PacketObservation,
        interface_id: u32,
        runtime: &GatewayRuntime,
    ) -> Result<IngressPacket, IngressError> {
        let mut packet = self.accept(observation, interface_id)?;

        if let Some(key) = packet.connection_key.as_ref() {
            packet.connection_found = runtime.connections.lookup(key).is_some();
        }

        Ok(packet)
    }
}

fn connection_key_from_parsed(parsed: &ParsedPacket) -> Option<ConnectionKey> {
    let src_ip = parsed.source_ip?;
    let dst_ip = parsed.destination_ip?;
    let src_port = parsed.source_port?;
    let dst_port = parsed.destination_port?;

    let protocol = match (parsed.protocol, parsed.transport) {
        (NetworkProtocol::Ipv4, TransportProtocol::Tcp)
        | (NetworkProtocol::Ipv6, TransportProtocol::Tcp) => ConnectionProtocol::Tcp,
        (NetworkProtocol::Ipv4, TransportProtocol::Udp)
        | (NetworkProtocol::Ipv6, TransportProtocol::Udp) => ConnectionProtocol::Udp,
        _ => return None,
    };

    Some(ConnectionKey::new(
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        protocol,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation() -> PacketObservation {
        let now = Timestamp::now();
        PacketObservation::new(
            ObservationId::new(1),
            BackendSource::WinDivert,
            now,
            now,
            Direction::Inbound,
            "eth0",
            Packet::new(vec![0x45, 0x00, 0x00, 0x14]),
        )
    }

    #[test]
    fn valid_ingress_packet_is_created() {
        let packet = IngressPacket::new(observation(), 1).unwrap();
        assert_eq!(packet.interface_id(), 1);
        assert_eq!(packet.packet_len(), 4);
        assert!(packet.parsed().is_none());
    }

    #[test]
    fn zero_interface_is_rejected() {
        assert!(IngressPacket::new(observation(), 0).is_none());
    }

    #[test]
    fn processor_rejects_invalid_packet() {
        let processor = IngressProcessor::new();
        let result = processor.accept(observation(), 1);
        assert_eq!(result, Err(IngressError::ParseFailed));
    }

    #[test]
    fn processor_rejects_zero_interface() {
        let processor = IngressProcessor::new();
        let result = processor.accept(observation(), 0);
        assert_eq!(result, Err(IngressError::InvalidInterface));
    }

    #[test]
    fn processor_rejects_empty_packet() {
        let processor = IngressProcessor::new();
        let mut packet = observation();
        packet.packet = Packet::new(vec![]);
        let result = processor.accept(packet, 1);
        assert_eq!(result, Err(IngressError::EmptyPacket));
    }

    #[test]
    fn observation_can_be_recovered() {
        let packet = IngressPacket::new(observation(), 1).unwrap();
        let recovered = packet.into_observation();
        assert_eq!(recovered.packet.len(), 4);
    }
}
