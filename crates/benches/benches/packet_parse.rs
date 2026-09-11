use criterion::{black_box, criterion_group, criterion_main, Criterion};
use network_core::{observation::{ObservationId, PacketObservation}, packet::Packet, timestamp::Timestamp, BackendSource, Direction};
use packet_parser::ParsedPacket;

fn tcp_observation() -> PacketObservation {
    let bytes = vec![
        0x00,0x11,0x22,0x33,0x44,0x55, 0x66,0x77,0x88,0x99,0xaa,0xbb, 0x08,0x00,
        0x45,0x00,0x00,0x32,0x00,0x01,0x00,0x00,0x40,0x06,0x00,0x00,
        0xc0,0xa8,0x01,0x01, 0xc0,0xa8,0x01,0x02,
        0x00,0x50,0x1f,0x90,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,
        0x50,0x02,0x20,0x00,0x00,0x00,0x00,0x00,
    ];
    let now = Timestamp::now();
    PacketObservation::new(
        ObservationId::new(1),
        BackendSource::WinDivert,
        now,
        now,
        Direction::Inbound,
        "bench0",
        Packet::new(bytes),
    )
}

fn bench_parse(c: &mut Criterion) {
    let observation = tcp_observation();
    c.bench_function("parse_tcp_observation", |b| {
        b.iter(|| ParsedPacket::parse(black_box(&observation)))
    });
}

criterion_group!(benches, bench_parse);
criterion_main!(benches);
