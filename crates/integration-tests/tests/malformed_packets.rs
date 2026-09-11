use network_core::{
    observation::{ObservationId, PacketObservation},
    packet::Packet,
    BackendSource, Direction, Timestamp,
};

fn observation(id: u64, bytes: Vec<u8>) -> PacketObservation {
    let now = Timestamp::now();
    PacketObservation::new(
        ObservationId::new(id),
        BackendSource::WinDivert,
        now,
        now,
        Direction::Inbound,
        "malformed-test",
        Packet::new(bytes),
    )
}

#[test]
fn malformed_lengths_are_rejected_without_panicking() {
    let valid = integration_tests::sample_ipv4_tcp_packet();
    let mut cases = vec![
        Vec::new(),
        vec![0; 1],
        vec![0; 7],
        vec![0; 8],
        vec![0; 13],
        vec![0; 14],
        vec![0; 19],
        vec![0; 34],
        vec![0; 47],
    ];

    let mut truncated = valid.clone();
    truncated.truncate(20);
    cases.push(truncated);

    let mut truncated_tcp = valid;
    truncated_tcp.truncate(40);
    cases.push(truncated_tcp);

    for (index, bytes) in cases.into_iter().enumerate() {
        let result = std::panic::catch_unwind(|| {
            packet_parser::ParsedPacket::parse(&observation(60_000 + index as u64, bytes))
        });
        assert!(result.is_ok(), "parser panicked for malformed case {index}");
        assert!(result.unwrap().is_err(), "malformed case {index} was accepted");
    }
}
