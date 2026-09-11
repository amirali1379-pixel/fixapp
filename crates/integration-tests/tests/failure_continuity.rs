use integration_tests::sample_observation;
use packet_bus::PacketBus;
use network_core::statistics::EngineStatistics;
use std::sync::atomic::Ordering;

#[test]
fn queue_pressure_is_observable_without_an_implicit_drop_policy() {
    let bus = PacketBus::new(1);
    bus.publish(sample_observation(500)).unwrap();
    assert!(bus.publish(sample_observation(501)).is_err());
    assert_eq!(bus.len(), 1);
}

#[test]
fn statistics_keep_failure_categories_separate() {
    let stats = EngineStatistics::new();
    stats.drops_host_requested.fetch_add(1, Ordering::Relaxed);
    stats.drops_safety_error.fetch_add(2, Ordering::Relaxed);
    stats.drops_backend_failure.fetch_add(3, Ordering::Relaxed);
    assert_eq!(stats.drops_host_requested.load(Ordering::Relaxed), 1);
    assert_eq!(stats.drops_safety_error.load(Ordering::Relaxed), 2);
    assert_eq!(stats.drops_backend_failure.load(Ordering::Relaxed), 3);
}

#[test]
fn raw_observation_survives_parser_failure_as_authoritative_data() {
    let observation = sample_observation(502);
    let raw = observation.packet.as_slice().to_vec();
    let parsed = packet_parser::ParsedPacket::parse(&observation);
    assert!(parsed.is_ok());
    assert_eq!(observation.packet.as_slice(), raw.as_slice());
}
