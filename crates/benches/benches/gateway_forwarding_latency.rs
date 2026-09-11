use criterion::{black_box, criterion_group, criterion_main, Criterion};
use gateway_capability::{EgressProcessor, ForwardingEntry, ForwardingTable, GatewayCapability, GatewayRuntime, IngressProcessor};
use network_core::{observation::{ObservationId, PacketObservation}, packet::Packet, timestamp::Timestamp, BackendSource, Direction};
use network_core::policy::GatewayPolicy;

fn observation() -> PacketObservation {
    let bytes = vec![
        0x00,0x11,0x22,0x33,0x44,0x55, 0x66,0x77,0x88,0x99,0xaa,0xbb, 0x08,0x00,
        0x45,0x00,0x00,0x1c,0x00,0x01,0x00,0x00,0x40,0x11,0x00,0x00,
        10,0,0,1, 10,0,0,2, 0x12,0x34,0x56,0x78,
        0x00,0x08,0x00,0x00,
    ];
    let now = Timestamp::now();
    PacketObservation::new(ObservationId::new(1), BackendSource::WinDivert, now, now, Direction::Inbound, "bench0", Packet::new(bytes))
}

fn bench_gateway_forwarding_path(c: &mut Criterion) {
    let ingress = IngressProcessor::new();
    let egress = EgressProcessor::new();
    let mut forwarding = ForwardingTable::new();
    forwarding.add(ForwardingEntry::new("10.0.0.0".parse().unwrap(), 24, 2, None).unwrap());

    c.bench_function("gateway_ingress_routing_egress_prepare", |b| {
        b.iter(|| {
            let ingress_packet = ingress.accept(observation(), 1).unwrap();
            let destination = ingress_packet.parsed().unwrap().destination_ip.unwrap();
            let decision = forwarding.resolve(destination).unwrap();
            black_box(egress.prepare_forwarding(ingress_packet.into_observation(), decision, [0x00,0x11,0x22,0x33,0x44,0x55]).unwrap());
        })
    });
}

fn bench_gateway_runtime(c: &mut Criterion) {
    c.bench_function("gateway_runtime_start_stop", |b| {
        b.iter(|| {
            let mut gateway = GatewayCapability::new(GatewayPolicy { enabled: true, ..GatewayPolicy::default() });
            black_box(gateway.start().unwrap());
            black_box(gateway.stop().unwrap());
        })
    });

    c.bench_function("gateway_runtime_cleanup", |b| {
        b.iter(|| {
            let mut runtime = GatewayRuntime::default();
            black_box(runtime.cleanup_expired());
        })
    });
}

criterion_group!(benches, bench_gateway_forwarding_path, bench_gateway_runtime);
criterion_main!(benches);
