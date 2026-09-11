use flow_engine::{FlowKey, FlowTable};
use std::time::Duration;

fn key(index: u16) -> FlowKey {
    FlowKey::new(
        "192.168.1.10".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        10_000u16.saturating_add(index),
        443,
        6,
    )
}

#[test]
fn many_flows_fill_table_without_exceeding_capacity() {
    let capacity = 2_000usize;
    let mut table = FlowTable::new(capacity, Duration::from_secs(300)).unwrap();

    for index in 0..capacity as u16 {
        table.record_packet(key(index), 1500, flow_engine::FlowDirection::Forward, Some(index as u64 + 1)).unwrap();
    }

    assert_eq!(table.len(), capacity);
    assert_eq!(table.stats().current_entries, capacity);
    assert_eq!(table.stats().max_entries, capacity);
    assert_eq!(table.capacity_available(), 0);
    assert!(table.record_packet(key(capacity as u16), 1500, flow_engine::FlowDirection::Forward, Some(capacity as u64 + 1)).is_err());
    assert_eq!(table.len(), capacity);
}

#[test]
fn repeated_packets_do_not_create_duplicate_flows() {
    let mut table = FlowTable::new(128, Duration::from_secs(300)).unwrap();
    let flow_key = key(1);

    for index in 0..10_000u64 {
        table.record_packet(flow_key.clone(), 128, flow_engine::FlowDirection::Forward, Some(index + 1)).unwrap();
    }

    assert_eq!(table.len(), 1);
    assert_eq!(table.stats().total_created, 1);
    assert_eq!(table.get(&flow_key).unwrap().packets, 10_000);
    assert_eq!(table.get(&flow_key).unwrap().bytes, 1_280_000);
}
