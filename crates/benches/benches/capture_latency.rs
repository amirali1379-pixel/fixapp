use criterion::{black_box, criterion_group, criterion_main, Criterion};
use network_core::{observation::{ObservationId, PacketObservation}, packet::Packet, timestamp::Timestamp, BackendSource, Direction};

fn bench_capture_observation(c: &mut Criterion) {
    let bytes = vec![0u8; 1500];
    c.bench_function("capture_observation_1500b", |b| {
        b.iter(|| {
            let now = Timestamp::now();
            black_box(PacketObservation::new(
                ObservationId::new(1), BackendSource::WinDivert, now, now,
                Direction::Inbound, "bench0", Packet::new(bytes.clone()),
            ))
        })
    });
}

criterion_group!(benches, bench_capture_observation);
criterion_main!(benches);