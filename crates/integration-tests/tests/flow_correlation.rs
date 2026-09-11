use integration_tests::sample_observation;
use flow_engine::{FlowDirection, FlowKey, FlowTable};
use std::time::Duration;

#[test]
fn correlation_produces_canonical_flow_identity() {
    let observation = sample_observation(200);
    let key = correlation::ObservationMatcher::to_flow_key(&observation).expect("TCP observation should correlate");
    assert_eq!(key.src_port, 80);
    assert_eq!(key.dst_port, 8080);
}

#[test]
fn flow_table_updates_forward_and_reverse_counters() {
    let observation = sample_observation(201);
    let key = correlation::ObservationMatcher::to_flow_key(&observation).unwrap();
    let local = FlowKey::new(key.src_ip, key.dst_ip, key.src_port, key.dst_port, 6);
    let mut table = FlowTable::new(16, Duration::from_secs(30)).unwrap();
    table.record_packet(local.clone(), 40, FlowDirection::Forward, Some(1)).unwrap();
    table.record_packet(local.reverse(), 20, FlowDirection::Reverse, Some(2)).unwrap();
    let flow = table.get(&local).unwrap();
    assert_eq!(flow.packet_count(), 2);
    assert_eq!(flow.byte_count(), 60);
    assert_eq!(table.len(), 1);
}

#[test]
fn duplicate_observation_does_not_create_multiple_logical_flows() {
    let first = sample_observation(202);
    let second = sample_observation(202);
    let k1 = correlation::ObservationMatcher::to_flow_key(&first).unwrap();
    let k2 = correlation::ObservationMatcher::to_flow_key(&second).unwrap();
    assert_eq!(k1, k2);
    let dedup = correlation::DedupFilter::new(16);
    assert!(!dedup.is_duplicate(first.observation_id.0));
    assert!(dedup.is_duplicate(second.observation_id.0));
}
