use criterion::{black_box, criterion_group, criterion_main, Criterion};
use correlation::ObservationMatcher;
use network_core::{
    observation::{ObservationId, PacketObservation},
    packet::Packet,
    timestamp::Timestamp,
    BackendSource, Direction,
};

fn ipv4_udp_ethernet() -> Vec<u8> {
    vec![
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x08, 0x00,
        0x45, 0x00, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,
        10, 0, 0, 1,
        10, 0, 0, 2,
        0x12, 0x34, 0x56, 0x78,
        0x00, 0x0c, 0x00, 0x00,
        0, 0, 0, 0,
    ]
}

fn bench_correlation(c: &mut Criterion) {
    let now = Timestamp::now();
    let observation = PacketObservation::new(
        ObservationId::new(1),
        BackendSource::WinDivert,
        now,
        now,
        Direction::Inbound,
        "bench0",
        Packet::new(ipv4_udp_ethernet()),
    );

    c.bench_function("observation_to_flow_key", |b| {
        b.iter(|| black_box(ObservationMatcher::to_flow_key(black_box(&observation))))
    });
}

criterion_group!(benches, bench_correlation);
criterion_main!(benches);
