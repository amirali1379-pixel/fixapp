use criterion::{black_box, criterion_group, criterion_main, Criterion};
use packet_bus::BufferPool;

fn bench_acquire_release(c: &mut Criterion) {
    let pool = BufferPool::new(1000, 4096).unwrap();

    c.bench_function("pool_acquire_release", |b| {
        b.iter(|| {
            let buffer = pool.acquire().unwrap();
            black_box(pool.release(buffer).unwrap());
        })
    });

    let pool = BufferPool::new(1000, 4096).unwrap();
    pool.preallocate(500);
    c.bench_function("pool_reuse_preallocated", |b| {
        b.iter(|| {
            let buffer = pool.acquire().unwrap();
            black_box(pool.release(buffer).unwrap());
        })
    });
}

criterion_group!(benches, bench_acquire_release);
criterion_main!(benches);
