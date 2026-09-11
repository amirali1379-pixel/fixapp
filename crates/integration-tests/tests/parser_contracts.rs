use integration_tests::sample_observation;
use network_core::{observation::{ObservationId, PacketObservation}, packet::Packet, BackendSource, Direction, Timestamp};

#[test]
fn parses_ethernet_ipv4_tcp_without_mutating_raw_bytes() {
    let observation = sample_observation(100);
    let before = observation.packet.as_slice().to_vec();
    let parsed = packet_parser::ParsedPacket::parse(&observation).unwrap();
    assert_eq!(parsed.protocol, packet_parser::NetworkProtocol::Ipv4);
    assert_eq!(parsed.transport, packet_parser::TransportProtocol::Tcp);
    assert_eq!(observation.packet.as_slice(), before.as_slice());
}

#[test]
fn malformed_short_packet_is_rejected_safely() {
    let now = Timestamp::now();
    let observation = PacketObservation::new(
        ObservationId::new(101), BackendSource::WinDivert, now, now,
        Direction::Inbound, "test0", Packet::new(vec![0u8; 8]),
    );
    assert!(packet_parser::ParsedPacket::parse(&observation).is_err());
}

#[test]
fn stacked_vlan_path_is_bounds_checked() {
    let mut bytes = integration_tests::sample_ipv4_tcp_packet();
    bytes[12] = 0x81; bytes[13] = 0x00;
    let now = Timestamp::now();
    let observation = PacketObservation::new(
        ObservationId::new(102), BackendSource::WinDivert, now, now,
        Direction::Inbound, "test0", Packet::new(bytes),
    );
    let _ = packet_parser::ParsedPacket::parse(&observation);
}
