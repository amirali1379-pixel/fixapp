use criterion::{black_box, criterion_group, criterion_main, Criterion};
use metadata_engine::MetadataCache;

fn bench_metadata(c: &mut Criterion) {
    let cache = MetadataCache::new(4096);
    cache.insert("example.com", "93.184.216.34", 60);

    c.bench_function("metadata_cache_hit", |b| {
        b.iter(|| black_box(cache.get(black_box("example.com"))))
    });

    c.bench_function("metadata_cache_insert", |b| {
        let mut id = 0u64;
        b.iter(|| {
            id = id.wrapping_add(1);
            cache.insert(&format!("host-{id}"), "127.0.0.1", 60);
            black_box(id);
        })
    });
}

criterion_group!(benches, bench_metadata);
criterion_main!(benches);