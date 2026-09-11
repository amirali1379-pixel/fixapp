use network_core::{
    observation::{ObservationId, PacketObservation},
    packet::Packet,
    BackendSource, Direction, Timestamp,
};
use packet_bus::PacketBus;
use std::collections::HashSet;

#[test]
fn many_interfaces_remain_distinguishable_under_load() {
    let bus = PacketBus::new(512);
    let now = Timestamp::now();

    for interface_id in 0..256u32 {
        let observation = PacketObservation::new(
            ObservationId::new(50_000 + interface_id as u64),
            BackendSource::WinDivert,
            now,
            now,
            Direction::Inbound,
            interface_id.to_string(),
            Packet::new(integration_tests::sample_ipv4_tcp_packet()),
        );
        bus.publish(observation).unwrap();
    }

    let mut interfaces = HashSet::new();
    while let Some(observation) = bus.try_read().unwrap() {
        interfaces.insert(observation.interface_id);
    }

    assert_eq!(interfaces.len(), 256);
    assert!(bus.is_empty());
}
