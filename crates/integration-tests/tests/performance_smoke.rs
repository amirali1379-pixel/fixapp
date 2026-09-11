use integration_tests::sample_observation;
use packet_bus::PacketBus;
use std::time::Instant;

#[test]
fn parser_and_bus_smoke_remain_non_blocking_at_small_batch() {
    let bus = PacketBus::new(1024);
    let start = Instant::now();
    for id in 600..700 {
        bus.publish(sample_observation(id)).unwrap();
    }
    for _ in 0..100 {
        let observation = bus.try_read().unwrap().expect("queued observation");
        let _ = packet_parser::ParsedPacket::parse(&observation);
    }
    let elapsed = start.elapsed();
    assert!(elapsed.as_secs() < 5, "unexpectedly slow parser/bus smoke path: {:?}", elapsed);
}
