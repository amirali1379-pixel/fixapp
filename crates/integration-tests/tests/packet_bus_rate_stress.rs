use integration_tests::sample_observation;
use packet_bus::PacketBus;

#[test]
fn low_rate_workload_drains_without_growth() {
    let bus = PacketBus::new(64);
    for id in 400..410 {
        bus.publish(sample_observation(id)).unwrap();
        assert_eq!(bus.len(), 1);
        bus.try_read().unwrap().expect("queued observation");
    }
    assert!(bus.is_empty());
}

#[test]
fn normal_rate_workload_stays_within_capacity() {
    let capacity = 128;
    let bus = PacketBus::new(capacity);

    for id in 500..900 {
        if bus.publish(sample_observation(id)).is_err() {
            bus.try_read().unwrap().expect("full queue must have an item");
            bus.publish(sample_observation(id)).unwrap();
        }
        assert!(bus.len() <= capacity);
    }

    while bus.try_read().unwrap().is_some() {}
    assert!(bus.is_empty());
}

#[test]
fn high_rate_workload_never_exceeds_capacity() {
    let capacity = 256;
    let bus = PacketBus::new(capacity);

    for id in 1_000..21_000 {
        let _ = bus.publish(sample_observation(id));
        assert!(bus.len() <= capacity);
        if id % 3 == 0 {
            let _ = bus.try_read().unwrap();
        }
    }

    assert!(bus.len() <= capacity);
}

#[test]
fn burst_traffic_reports_rejections_at_capacity() {
    let capacity = 32;
    let bus = PacketBus::new(capacity);
    let mut accepted = 0usize;
    let mut rejected = 0usize;

    for id in 30_000..31_000 {
        match bus.publish(sample_observation(id)) {
            Ok(()) => accepted += 1,
            Err(_) => rejected += 1,
        }
        assert!(bus.len() <= capacity);
    }

    assert_eq!(accepted + rejected, 1_000);
    assert!(rejected > 0);
    assert_eq!(bus.len(), capacity);
}
