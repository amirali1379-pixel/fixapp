use std::net::IpAddr;

use network_core::{
    observation::{ObservationId, PacketObservation},
    packet::Packet,
    timestamp::Timestamp,
    BackendSource, Direction,
};

use crate::ForwardingDecision;

#[derive(Debug, PartialEq)]
pub struct EgressPacket {
    pub observation: PacketObservation,
    pub interface_id: u32,
    pub next_hop: Option<IpAddr>,
    pub neighbor_address: Option<[u8; 6]>,
}

impl EgressPacket {
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
            next_hop: None,
            neighbor_address: None,
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

    pub fn next_hop(&self) -> Option<IpAddr> {
        self.next_hop
    }

    pub fn neighbor_address(&self) -> Option<[u8; 6]> {
        self.neighbor_address
    }

    pub fn into_observation(self) -> PacketObservation {
        self.observation
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressError {
    InvalidInterface,
    EmptyPacket,
    InvalidNextHop,
    NeighborUnresolved,
}

#[derive(Debug, Default)]
pub struct EgressProcessor;

impl EgressProcessor {
    pub fn new() -> Self {
        Self
    }

    pub fn prepare(
        &self,
        observation: PacketObservation,
        interface_id: u32,
    ) -> Result<EgressPacket, EgressError> {
        if interface_id == 0 {
            return Err(EgressError::InvalidInterface);
        }
        if observation.packet.is_empty() {
            return Err(EgressError::EmptyPacket);
        }
        EgressPacket::new(observation, interface_id)
            .ok_or(EgressError::InvalidInterface)
    }

    pub fn prepare_forwarding(
        &self,
        observation: PacketObservation,
        decision: ForwardingDecision,
        neighbor_address: [u8; 6],
    ) -> Result<EgressPacket, EgressError> {
        if decision.interface_id == 0 {
            return Err(EgressError::InvalidInterface);
        }

        if decision.next_hop.is_unspecified() {
            return Err(EgressError::InvalidNextHop);
        }

        if neighbor_address == [0; 6] {
            return Err(EgressError::NeighborUnresolved);
        }

        let mut packet = self.prepare(observation, decision.interface_id)?;
        packet.next_hop = Some(decision.next_hop);
        packet.neighbor_address = Some(neighbor_address);
        Ok(packet)
    }
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

    fn decision() -> ForwardingDecision {
        ForwardingDecision {
            interface_id: 2,
            next_hop: "192.168.1.1".parse().unwrap(),
        }
    }

    #[test]
    fn valid_egress_packet_is_created() {
        let packet = EgressPacket::new(observation(), 1).unwrap();
        assert_eq!(packet.interface_id(), 1);
        assert_eq!(packet.packet_len(), 4);
        assert_eq!(packet.next_hop(), None);
        assert_eq!(packet.neighbor_address(), None);
    }

    #[test]
    fn zero_interface_is_rejected() {
        assert!(EgressPacket::new(observation(), 0).is_none());
    }

    #[test]
    fn empty_packet_is_rejected() {
        let mut packet = observation();
        packet.packet = Packet::new(vec![]);
        assert!(EgressPacket::new(packet, 1).is_none());
    }

    #[test]
    fn processor_prepares_valid_packet() {
        let processor = EgressProcessor::new();
        let result = processor.prepare(observation(), 1);
        assert!(result.is_ok());
    }

    #[test]
    fn processor_rejects_invalid_interface() {
        let processor = EgressProcessor::new();
        let result = processor.prepare(observation(), 0);
        assert_eq!(result, Err(EgressError::InvalidInterface));
    }

    #[test]
    fn processor_rejects_empty_packet() {
        let processor = EgressProcessor::new();
        let mut packet = observation();
        packet.packet = Packet::new(vec![]);
        let result = processor.prepare(packet, 1);
        assert_eq!(result, Err(EgressError::EmptyPacket));
    }

    #[test]
    fn forwarding_result_is_preserved_for_next_stage() {
        let processor = EgressProcessor::new();
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let packet = processor
            .prepare_forwarding(observation(), decision(), mac)
            .unwrap();

        assert_eq!(packet.interface_id(), 2);
        assert_eq!(packet.next_hop(), Some("192.168.1.1".parse().unwrap()));
        assert_eq!(packet.neighbor_address(), Some(mac));
    }

    #[test]
    fn unresolved_neighbor_is_rejected() {
        let processor = EgressProcessor::new();
        let result = processor.prepare_forwarding(observation(), decision(), [0; 6]);
        assert_eq!(result, Err(EgressError::NeighborUnresolved));
    }

    #[test]
    fn invalid_next_hop_is_rejected() {
        let processor = EgressProcessor::new();
        let result = processor.prepare_forwarding(
            observation(),
            ForwardingDecision {
                interface_id: 2,
                next_hop: "0.0.0.0".parse().unwrap(),
            },
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        );
        assert_eq!(result, Err(EgressError::InvalidNextHop));
    }

    #[test]
    fn observation_can_be_recovered() {
        let packet = EgressPacket::new(observation(), 1).unwrap();
        let recovered = packet.into_observation();
        assert_eq!(recovered.packet.len(), 4);
    }
}
