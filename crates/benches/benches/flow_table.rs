use criterion::{black_box, criterion_group, criterion_main, Criterion};
use flow_engine::{Flow, FlowKey, FlowTable};

fn bench_insert_lookup(c: &mut Criterion) {
    let mut table = FlowTable::with_defaults(10_000).unwrap();
    let key = FlowKey::new(
        "192.168.1.1".parse().unwrap(),
        "192.168.1.2".parse().unwrap(),
        12345,
        80,
        6,
    );

    c.bench_function("flow_insert_remove", |b| {
        b.iter(|| {
            let flow = Flow::new(black_box(key.clone()));
            table.insert(flow).unwrap();
            black_box(table.remove(black_box(&key)));
        })
    });

    table.insert(Flow::new(key.clone())).unwrap();
    c.bench_function("flow_lookup", |b| {
        b.iter(|| black_box(table.get(black_box(&key))))
    });
}

criterion_group!(benches, bench_insert_lookup);
criterion_main!(benches);
