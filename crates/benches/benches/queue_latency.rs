use criterion::{black_box, criterion_group, criterion_main, Criterion};
use network_core::{
    observation::{ObservationId, PacketObservation},
    packet::Packet,
    timestamp::Timestamp,
    BackendSource, Direction,
};
use packet_bus::ObservationQueue;

fn observation(id: u64) -> PacketObservation {
    let now = Timestamp::now();
    PacketObservation::new(
        ObservationId::new(id),
        BackendSource::WinDivert,
        now,
        now,
        Direction::Inbound,
        "bench0",
        Packet::new(vec![0u8; 128]),
    )
}

fn bench_queue(c: &mut Criterion) {
    c.bench_function("queue_try_enqueue_dequeue", |b| {
        let queue = ObservationQueue::new(1024);
        let mut id = 0u64;
        b.iter(|| {
            id = id.wrapping_add(1);
            queue.try_enqueue(observation(black_box(id))).unwrap();
            black_box(queue.try_dequeue().unwrap().unwrap());
        })
    });
}

criterion_group!(benches, bench_queue);
criterion_main!(benches);
