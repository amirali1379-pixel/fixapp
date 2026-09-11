use std::time::Duration;

use backend_manager::{BackendCapability, BackendDescriptor, BackendLifecycle, BackendManager, CapabilitySet, FailoverPolicy};
use flow_engine::{FlowDirection, FlowTable};
use network_core::{EngineState, Direction, observation::{ObservationId, PacketObservation}, packet::Packet, BackendSource, Timestamp};
use packet_bus::{BufferPool, PacketBus};

use integration_tests::sample_observation;

#[test]
fn engine_lifecycle() {
    let state = EngineState::new();
    assert!(!state.is_initialized());
    assert!(state.init().is_ok());
    assert!(state.is_initialized());
    assert!(state.init().is_err());
    assert!(state.shutdown().is_ok());
    assert!(!state.is_initialized());
}

#[test]
fn packet_bus_to_flow_table_pipeline() {
    let bus = PacketBus::new(100);
    let observation = sample_observation(1);
    let packet_len = observation.packet_length;
    assert!(bus.publish(observation).is_ok());
    let dequeued = bus.try_read().unwrap().expect("observation must reach bus");
    assert_eq!(dequeued.packet_length, packet_len);
    let parsed = packet_parser::ParsedPacket::parse(&dequeued).unwrap();
    assert_eq!(parsed.protocol, packet_parser::NetworkProtocol::Ipv4);
    assert_eq!(parsed.transport, packet_parser::TransportProtocol::Tcp);
    let core_key = correlation::ObservationMatcher::to_flow_key(&dequeued).unwrap();
    let local_key = flow_engine::FlowKey::new(core_key.src_ip, core_key.dst_ip, core_key.src_port, core_key.dst_port, match core_key.protocol { network_core::Protocol::Tcp => 6, network_core::Protocol::Udp => 17, network_core::Protocol::Icmp => 1, network_core::Protocol::IcmpV6 => 58, network_core::Protocol::Other(value) => value });
    let mut table = FlowTable::new(100, Duration::from_secs(30)).unwrap();
    table.record_packet(local_key.clone(), packet_len, FlowDirection::Forward, Some(1_000)).unwrap();
    table.record_packet(local_key.reverse(), 10, FlowDirection::Reverse, Some(2_000)).unwrap();
    let flow = table.get(&local_key).unwrap();
    assert_eq!(flow.packet_count(), 2);
    assert_eq!(flow.byte_count(), packet_len as u64 + 10);
    assert_eq!(table.len(), 1);
    bus.release_processing(dequeued.observation_id).unwrap();
}

#[test]
fn backend_manager_registers_and_tracks_capabilities() {
    let manager = BackendManager::new();
    let descriptor = BackendDescriptor::new("integration-backend", "1.0", "software test backend", CapabilitySet::from([BackendCapability::Capture, BackendCapability::Ipv4]));
    manager.register(descriptor).unwrap();
    assert!(manager.contains("integration-backend"));
    assert!(manager.supports("integration-backend", BackendCapability::Capture).unwrap());
}

#[test]
fn backend_failure_uses_healthy_fallback_without_fabricating_capability() {
    let manager = BackendManager::new();
    let primary = BackendDescriptor::new("primary", "1.0", "primary test backend", CapabilitySet::from([BackendCapability::Capture, BackendCapability::Ipv4]));
    let fallback = BackendDescriptor::new("fallback", "1.0", "fallback test backend", CapabilitySet::from([BackendCapability::Capture, BackendCapability::Ipv4]));
    manager.register(primary).unwrap();
    manager.register(fallback).unwrap();
    manager.set_lifecycle("primary", BackendLifecycle::Running).unwrap();
    manager.set_lifecycle("fallback", BackendLifecycle::Running).unwrap();
    manager.set_failover_policy(FailoverPolicy::PreferHealthy).unwrap();

    manager.set_lifecycle("primary", BackendLifecycle::Failed).unwrap();
    assert_eq!(manager.find_healthy_capable(BackendCapability::Capture), vec!["fallback".to_string()]);
    assert_eq!(manager.select_backend(BackendCapability::Capture), Some("fallback".to_string()));
}

#[test]
fn buffer_pool_is_bounded() {
    let pool = BufferPool::new(100, 1024).unwrap();
    let mut buffers = Vec::new();
    for _ in 0..100 { buffers.push(pool.acquire().unwrap()); }
    assert!(pool.acquire().is_err());
    for buffer in buffers { pool.release(buffer).unwrap(); }
    assert_eq!(pool.available(), 100);
}

#[test]
fn parser_handles_icmp_ipv4() {
    let mut raw = sample_observation(2).packet.into_data();
    raw[23] = 1;
    raw.truncate(14 + 20 + 8);
    raw[16] = 0; raw[17] = 42;
    raw[14] = 0x45;
    let now = Timestamp::now();
    let observation = PacketObservation::new(ObservationId::new(2), BackendSource::WinDivert, now, now, Direction::Inbound, "integration0", Packet::new(raw));
    let parsed = packet_parser::ParsedPacket::parse(&observation).unwrap();
    assert_eq!(parsed.transport, packet_parser::TransportProtocol::Icmp);
}

#[test]
fn final_engine_runtime_processes_and_releases_observation() {
    let config = network_engine::EngineConfig { queue_capacity: 16, pool_max_size: 8, buffer_capacity: 2048, max_flows: 128 };
    let mut engine = network_engine::EngineRuntime::initialize(&config).unwrap();
    let observation = sample_observation(10);
    let id = observation.observation_id;
    engine.ingest_observation(observation).unwrap();
    assert_eq!(engine.packet_bus.len(), 1);
    assert!(engine.process_one().unwrap().is_some());
    assert_eq!(engine.packet_bus.len(), 0);
    assert!(engine.metadata.lock().unwrap().get(id).is_some());
    engine.shutdown().unwrap();
}

#[test]
fn final_engine_shutdown_drains_queued_observations() {
    let config = network_engine::EngineConfig { queue_capacity: 16, pool_max_size: 8, buffer_capacity: 2048, max_flows: 128 };
    let mut engine = network_engine::EngineRuntime::initialize(&config).unwrap();
    engine.ingest_observation(sample_observation(11)).unwrap();
    engine.ingest_observation(sample_observation(12)).unwrap();
    assert_eq!(engine.packet_bus.len(), 2);
    engine.shutdown().unwrap();
    assert_eq!(engine.packet_bus.len(), 0);
}

#[test]
fn final_engine_does_not_fabricate_metadata_for_unknown_observation() {
    let config = network_engine::EngineConfig { queue_capacity: 16, pool_max_size: 8, buffer_capacity: 2048, max_flows: 128 };
    let mut engine = network_engine::EngineRuntime::initialize(&config).unwrap();
    let unknown = ObservationId::new(0x7fff_ffff);
    assert!(engine.metadata.lock().unwrap().get(unknown).is_none());
    engine.shutdown().unwrap();
}

#[test]
fn final_engine_rejects_empty_observation_before_bus_publish() {
    let config = network_engine::EngineConfig { queue_capacity: 16, pool_max_size: 8, buffer_capacity: 2048, max_flows: 128 };
    let mut engine = network_engine::EngineRuntime::initialize(&config).unwrap();
    let now = Timestamp::now();
    let observation = PacketObservation::new(
        ObservationId::new(0x7fff_fffe),
        BackendSource::WinDivert,
        now,
        now,
        Direction::Inbound,
        "integration0",
        Packet::new(Vec::new()),
    );
    assert!(engine.ingest_observation(observation).is_err());
    assert_eq!(engine.packet_bus.len(), 0);
    engine.shutdown().unwrap();
}

#[cfg(windows)]
#[test]
fn final_dll_c_abi_lifecycle_is_linked_and_callable() {
    #[repr(C)]
    struct AbiInitConfig {
        queue_capacity: u32,
        pool_max_size: u32,
        buffer_capacity: u32,
        max_flows: u32,
    }

    #[repr(C)]
    struct AbiPacketDescriptor {
        packet_handle: u64,
        data: *const std::ffi::c_void,
        len: u32,
        backend_source: i32,
        direction: i32,
    }

    #[repr(C)]
    struct AbiStatistics {
        packets_received: u64,
        bytes_received: u64,
        packets_dropped: u64,
        packets_forwarded: u64,
        flows_active: u64,
    }

    unsafe extern "C" {
        fn network_init(config: *const AbiInitConfig) -> i32;
        fn network_shutdown() -> i32;
        fn network_is_initialized() -> i32;
        fn packet_inject(data: *const std::ffi::c_void, len: u32, backend_source: i32, direction: i32, interface_id: u32) -> i32;
        fn packet_read(out: *mut AbiPacketDescriptor) -> i32;
        fn packet_pass(packet_handle: u64) -> i32;
        fn network_stats(out: *mut AbiStatistics) -> i32;
    }

    let config = AbiInitConfig {
        queue_capacity: 16,
        pool_max_size: 8,
        buffer_capacity: 2048,
        max_flows: 128,
    };

    unsafe {
        assert_eq!(network_init(&config), 0);
        assert_eq!(network_is_initialized(), 1);

        let packet = integration_tests::sample_ipv4_tcp_packet();
        assert_eq!(packet_inject(packet.as_ptr() as *const std::ffi::c_void, packet.len() as u32, 0, 0, 0), 0);

        let mut descriptor = AbiPacketDescriptor {
            packet_handle: 0,
            data: std::ptr::null(),
            len: 0,
            backend_source: -1,
            direction: -1,
        };
        assert_eq!(packet_read(&mut descriptor), 0);
        assert_ne!(descriptor.packet_handle, 0);
        assert_eq!(descriptor.len, packet.len() as u32);
        assert_eq!(packet_pass(descriptor.packet_handle), 0);

        let mut stats = AbiStatistics {
            packets_received: 0,
            bytes_received: 0,
            packets_dropped: 0,
            packets_forwarded: 0,
            flows_active: 0,
        };
        assert_eq!(network_stats(&mut stats), 0);
        assert!(stats.packets_received >= 1);
        assert!(stats.bytes_received >= packet.len() as u64);

        assert_eq!(network_shutdown(), 0);
        assert_eq!(network_is_initialized(), 0);
    }
}
