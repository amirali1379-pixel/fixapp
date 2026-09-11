use integration_tests::sample_observation;
use packet_bus::PacketBus;

#[test]
fn queue_full_is_observable_and_bounded() {
    let bus = PacketBus::new(2);
    assert!(bus.publish(sample_observation(300)).is_ok());
    assert!(bus.publish(sample_observation(301)).is_ok());
    assert!(bus.publish(sample_observation(302)).is_err());
    assert_eq!(bus.len(), 2);
}

#[test]
fn close_prevents_new_publication() {
    let bus = PacketBus::new(4);
    bus.close();
    assert!(bus.publish(sample_observation(303)).is_err());
}

#[test]
fn queue_drains_without_reordering_observations() {
    let bus = PacketBus::new(8);
    for id in 310..315 { bus.publish(sample_observation(id)).unwrap(); }
    for id in 310..315 {
        let observation = bus.try_read().unwrap().expect("queued observation");
        assert_eq!(observation.observation_id.0, id);
    }
    assert!(bus.try_read().unwrap().is_none());
}
