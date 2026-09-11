use integration_tests::sample_observation;
use flow_engine::{FlowDirection, FlowKey, FlowTable};
use packet_bus::BufferPool;
use std::time::Duration;

#[test]
fn buffer_pool_never_exceeds_configured_capacity() {
    let pool = BufferPool::new(4, 512).unwrap();
    let a = pool.acquire().unwrap();
    let b = pool.acquire().unwrap();
    let c = pool.acquire().unwrap();
    let d = pool.acquire().unwrap();
    assert!(pool.acquire().is_err());
    pool.release(a).unwrap(); pool.release(b).unwrap(); pool.release(c).unwrap(); pool.release(d).unwrap();
    assert_eq!(pool.available(), 4);
}

#[test]
fn flow_table_respects_maximum_capacity() {
    let mut table = FlowTable::new(2, Duration::from_secs(60)).unwrap();
    for id in 400..402 {
        let observation = sample_observation(id);
        let key = correlation::ObservationMatcher::to_flow_key(&observation).unwrap();
        let local = FlowKey::new(key.src_ip, key.dst_ip, key.src_port + id as u16, key.dst_port, 6);
        table.record_packet(local, observation.packet_length, FlowDirection::Forward, Some(id)).unwrap();
    }
    assert!(table.len() <= 2);
    assert_eq!(table.max_entries(), 2);
}
