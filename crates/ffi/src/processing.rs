// crates/ffi/src/processing.rs
//
// Processing pipeline for the Engine.
//
// Two related concerns live here:
//
//   1. The EngineRuntime processing pipeline (dedup, flow recording,
//      metadata aggregation, worker thread). This is the live path.
//
//   2. The legacy synchronous observation processor
//      (`process_observation_legacy`, `process_observation_with_policy`)
//      preserved for callers that need a `&mut FlowTable` based,
//      side-effect-free parse-and-record step.
//
// Both are kept. The EngineRuntime path owns the runtime state; the
// legacy path owns no runtime state and can be used by tests or by
// future synchronous callers.

#![forbid(unsafe_code)]

use std::sync::atomic::Ordering;
use std::sync::mpsc::TrySendError;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use network_core::observation::PacketObservation;
use network_core::{EngineError, EngineErrorCode, EngineResult};

use flow_engine::{FlowDirection, FlowKey};
use packet_parser::{NetworkProtocol, ParsedPacket, TransportProtocol};

use correlation::dedup::DedupFilter;
use correlation::identity::ObservationIdentity;
use correlation::matcher::ObservationMatcher;
use metadata_engine::{WorkItem, WorkResult, WorkerPool};

use crate::decision::{evaluate_packet, PacketDecision};
use crate::engine::EngineRuntime;
use crate::load_balancer::WorkKind;

// ─────────────────────────────────────────────────────────────────────
// Legacy synchronous processing path
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessedObservation {
    pub observation_id: network_core::ObservationId,
    pub backend_source: network_core::BackendSource,
    pub parsed: ParsedPacket,
    pub flow_key: Option<FlowKey>,
    pub decision: PacketDecision,
    pub packet: network_core::Packet,
}

pub fn flow_key_from_parsed(parsed: &ParsedPacket) -> Option<FlowKey> {
    let source_ip = parsed.source_ip?;
    let destination_ip = parsed.destination_ip?;
    let protocol = match parsed.transport {
        TransportProtocol::Tcp => 6,
        TransportProtocol::Udp => 17,
        TransportProtocol::Icmp => 1,
        TransportProtocol::Icmpv6 => 58,
        TransportProtocol::Unknown => return None,
    };
    Some(FlowKey::new(
        source_ip,
        destination_ip,
        parsed.source_port.unwrap_or(0),
        parsed.destination_port.unwrap_or(0),
        protocol,
    ))
}

pub fn flow_direction(direction: network_core::Direction) -> FlowDirection {
    match direction {
        network_core::Direction::Inbound => FlowDirection::Reverse,
        network_core::Direction::Outbound | network_core::Direction::Unknown => FlowDirection::Forward,
    }
}

/// Legacy synchronous observation processor.
///
/// Renamed from the historical `process_observation` to avoid clashing
/// with `EngineRuntime::process_observation`, which is the live
/// runtime path.
pub fn process_observation_legacy(
    observation: PacketObservation,
    flow_table: &mut flow_engine::FlowTable,
) -> Result<ProcessedObservation, EngineError> {
    let backend_source = observation.backend_source;
    let direction = observation.direction;
    let observation_id = observation.observation_id;
    let packet_length = observation.packet_length;
    let capture_timestamp = observation.capture_timestamp;
    let parsed = ParsedPacket::parse(&observation)?;
    let flow_key = flow_key_from_parsed(&parsed);
    let packet = observation.packet;

    if let Some(key) = &flow_key {
        flow_table.record_packet(
            key.clone(),
            packet_length,
            flow_direction(direction),
            Some(capture_timestamp.as_nanos()),
        )?;
    }

    Ok(ProcessedObservation {
        observation_id,
        backend_source,
        parsed,
        flow_key,
        decision: PacketDecision::Pass,
        packet,
    })
}

pub fn process_observation_with_policy(
    observation: PacketObservation,
    flow_table: &mut flow_engine::FlowTable,
    policy: &network_core::PacketActionPolicyConfig,
) -> Result<ProcessedObservation, EngineError> {
    let direction = observation.direction;
    let mut processed = process_observation_legacy(observation, flow_table)?;
    processed.decision = evaluate_packet(&processed.parsed, direction, policy);
    Ok(processed)
}

#[inline]
pub fn is_flow_trackable(parsed: &ParsedPacket) -> bool {
    matches!(parsed.protocol, NetworkProtocol::Ipv4 | NetworkProtocol::Ipv6)
        && flow_key_from_parsed(parsed).is_some()
}

pub fn invalid_processing_state(message: &str) -> EngineError {
    EngineError::with_message(EngineErrorCode::InvalidStateTransition, message)
}

// ─────────────────────────────────────────────────────────────────────
// EngineRuntime processing pipeline
// ─────────────────────────────────────────────────────────────────────

fn to_flow_engine_key(key: network_core::FlowKey) -> flow_engine::FlowKey {
    flow_engine::FlowKey::new(
        key.src_ip,
        key.dst_ip,
        key.src_port,
        key.dst_port,
        key.protocol.to_ip_protocol(),
    )
}

const WORKER_IDLE_SLEEP: Duration = Duration::from_millis(1);

impl EngineRuntime {
    fn processing_context(&self) -> ProcessingShared {
        ProcessingShared {
            packet_bus: Arc::clone(&self.packet_bus),
            flow_table: Arc::clone(&self.flow_table),
            dedup: Arc::clone(&self.dedup),
            metadata_workers: Arc::clone(&self.metadata_workers),
            metadata: Arc::clone(&self.metadata),
            statistics: Arc::clone(&self.statistics),
            state: Arc::clone(&self.state),
        }
    }

    pub(crate) fn process_observation(
        &self,
        observation: &PacketObservation,
    ) -> EngineResult<()> {
        self.require_running()?;
        process_observation_shared(&self.processing_context(), observation)
    }

    /// Plans multi-backend coordination for an observation.
    pub fn plan_coordination(
        &self,
        observation: &PacketObservation,
        required: &[backend_manager::BackendCapability],
    ) -> crate::coordination::CoordinatedObservation {
        self.coordinator.coordinate(observation.clone(), required)
    }

    /// Plans load-balanced processing for an observation.
    pub fn plan_load_balanced_processing(
        &self,
        observation: &PacketObservation,
        required: &[backend_manager::BackendCapability],
        work_kind: WorkKind,
    ) -> crate::coordination::LoadBalancedPlan {
        self.coordinator
            .plan_load_balanced_processing(observation.clone(), required, work_kind)
    }

    pub fn process_one(&self) -> EngineResult<Option<()>> {
        self.require_running()?;
        let observation = match self.packet_bus.try_read()? {
            Some(value) => value,
            None => return Ok(None),
        };
        let observation_id = observation.observation_id;
        let result = process_observation_shared(&self.processing_context(), &observation);
        let release = self.packet_bus.release_processing(observation_id);
        drop(observation);
        result.and(release).map(|()| Some(()))
    }

    pub fn start_processing_worker(&self) -> EngineResult<()> {
        self.require_running()?;
        let mut guard = self.processing_thread.lock().map_err(|_| {
            EngineError::with_message(
                EngineErrorCode::InternalError,
                "processing thread handle mutex poisoned",
            )
        })?;
        if guard.is_some() {
            return Ok(());
        }
        self.processing_stop.store(false, Ordering::SeqCst);
        let shared = self.processing_context();
        let stop = Arc::clone(&self.processing_stop);
        let handle = std::thread::Builder::new()
            .name("network-engine-processing".into())
            .spawn(move || processing_worker_loop(shared, stop))
            .map_err(|_| {
                EngineError::with_message(
                    EngineErrorCode::InternalError,
                    "failed to spawn processing worker",
                )
            })?;
        *guard = Some(handle);
        Ok(())
    }
}

#[derive(Clone)]
struct ProcessingShared {
    packet_bus: Arc<packet_bus::PacketBus>,
    flow_table: Arc<Mutex<flow_engine::FlowTable>>,
    dedup: Arc<DedupFilter>,
    metadata_workers: Arc<Mutex<WorkerPool>>,
    metadata: Arc<Mutex<network_core::metadata::MetadataStore>>,
    statistics: Arc<network_core::statistics::EngineStatistics>,
    state: Arc<network_core::EngineState>,
}

fn process_observation_shared(
    shared: &ProcessingShared,
    observation: &PacketObservation,
) -> EngineResult<()> {
    let parsed = match ParsedPacket::parse(observation) {
        Ok(value) => Some(value),
        Err(_) => {
            shared.statistics.total_errors.fetch_add(1, Ordering::Relaxed);
            None
        }
    };

    let identity = ObservationIdentity::from_observation(observation);
    if !shared.dedup.is_duplicate(identity.source_hash) {
        if let Some(flow_key) = ObservationMatcher::to_flow_key(observation) {
            let direction = FlowDirection::from_network_direction(observation.direction);
            let mut table = shared.flow_table.lock().map_err(|_| {
                EngineError::with_message(
                    EngineErrorCode::InternalError,
                    "flow table mutex poisoned",
                )
            })?;
            let _ = table.record_packet(
                to_flow_engine_key(flow_key),
                observation.packet_length,
                direction,
                None,
            );
        }
    }

    {
        let mut metadata = shared.metadata.lock().map_err(|_| {
            EngineError::with_message(
                EngineErrorCode::InternalError,
                "metadata mutex poisoned",
            )
        })?;
        for (key, value) in &observation.native_metadata {
            metadata.add(
                observation.observation_id,
                key,
                value,
                &format!("backend:{:?}", observation.backend_source),
            );
        }
        if !observation.provenance.is_empty() {
            metadata.add(
                observation.observation_id,
                "observation.provenance",
                &observation.provenance.join(","),
                "engine",
            );
        }
    }

    if let Some(parsed) = parsed {
        let mut workers = shared.metadata_workers.lock().map_err(|_| {
            EngineError::with_message(
                EngineErrorCode::InternalError,
                "metadata worker pool mutex poisoned",
            )
        })?;
        for address in [parsed.source_ip, parsed.destination_ip]
            .into_iter()
            .flatten()
        {
            match workers.enqueue(WorkItem::ReverseDnsLookup {
                observation_id: observation.observation_id,
                address,
            }) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    shared
                        .statistics
                        .queue_saturation_events
                        .fetch_add(1, Ordering::Relaxed);
                }
                Err(TrySendError::Disconnected(_)) => {
                    shared.statistics.total_errors.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    drain_metadata_results(shared)?;
    shared
        .statistics
        .total_packets_processed
        .fetch_add(1, Ordering::Relaxed);
    shared.statistics.total_bytes_processed.fetch_add(
        observation.packet_length as u64,
        Ordering::Relaxed,
    );
    Ok(())
}

fn drain_metadata_results(shared: &ProcessingShared) -> EngineResult<()> {
    loop {
        let result = {
            let workers = shared.metadata_workers.lock().map_err(|_| {
                EngineError::with_message(
                    EngineErrorCode::InternalError,
                    "metadata worker pool mutex poisoned",
                )
            })?;
            workers.try_recv_result()
        };
        match result {
            Ok(Some(WorkResult::ReverseDnsLookup {
                observation_id,
                address,
                hostname,
            })) => {
                let mut metadata = shared.metadata.lock().map_err(|_| {
                    EngineError::with_message(
                        EngineErrorCode::InternalError,
                        "metadata mutex poisoned",
                    )
                })?;
                if let Some(hostname) = hostname {
                    metadata.add(
                        observation_id,
                        "reverse_dns",
                        &hostname,
                        &format!("dns:{address}"),
                    );
                } else {
                    metadata.add(
                        observation_id,
                        "reverse_dns.error",
                        "resolution_failed",
                        "dns",
                    );
                }
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
    Ok(())
}

fn processing_worker_loop(
    shared: ProcessingShared,
    stop: Arc<std::sync::atomic::AtomicBool>,
) {
    while !stop.load(Ordering::SeqCst) && !shared.state.is_shutdown_requested() {
        match shared.packet_bus.try_read() {
            Ok(Some(observation)) => {
                let observation_id = observation.observation_id;
                if process_observation_shared(&shared, &observation).is_err() {
                    shared.statistics.total_errors.fetch_add(1, Ordering::Relaxed);
                }
                if shared.packet_bus.release_processing(observation_id).is_err() {
                    shared.statistics.total_errors.fetch_add(1, Ordering::Relaxed);
                }
                drop(observation);
            }
            Ok(None) => std::thread::sleep(WORKER_IDLE_SLEEP),
            Err(_) => {
                shared.statistics.total_errors.fetch_add(1, Ordering::Relaxed);
                std::thread::sleep(WORKER_IDLE_SLEEP);
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use network_core::{BackendSource, Direction, ObservationId, Packet, Timestamp};

    fn tcp_observation() -> PacketObservation {
        let mut bytes = vec![0u8; 54];
        bytes[12] = 0x08;
        bytes[13] = 0x00;
        bytes[14] = 0x45;
        bytes[16] = 0;
        bytes[17] = 40;
        bytes[23] = 6;
        bytes[26] = 10;
        bytes[27] = 0;
        bytes[28] = 0;
        bytes[29] = 1;
        bytes[30] = 8;
        bytes[31] = 8;
        bytes[32] = 8;
        bytes[33] = 8;
        bytes[34] = 0x30;
        bytes[35] = 0x39;
        bytes[36] = 0x01;
        bytes[37] = 0xbb;
        bytes[46] = 0x50;
        let now = Timestamp::now();
        PacketObservation::new(
            ObservationId::new(1),
            BackendSource::WinDivert,
            now,
            now,
            Direction::Outbound,
            "1",
            Packet::new(bytes),
        )
    }

    #[test]
    fn tcp_packet_creates_flow() {
        let mut table = flow_engine::FlowTable::with_defaults(16).unwrap();
        let result = process_observation_legacy(tcp_observation(), &mut table).unwrap();
        assert_eq!(result.parsed.transport, TransportProtocol::Tcp);
        assert!(result.flow_key.is_some());
        assert_eq!(result.decision, PacketDecision::Pass);
        assert_eq!(result.packet.len(), 54);
        assert_eq!(table.len(), 1);
        assert_eq!(table.values().next().unwrap().packets, 1);
        assert_eq!(result.backend_source, BackendSource::WinDivert);
    }

    #[test]
    fn arp_does_not_create_flow() {
        let mut bytes = vec![0u8; 42];
        bytes[12] = 0x08;
        bytes[13] = 0x06;
        bytes[14] = 0;
        bytes[15] = 1;
        bytes[16] = 0x08;
        bytes[17] = 0;
        bytes[18] = 6;
        bytes[19] = 4;
        let now = Timestamp::now();
        let observation = PacketObservation::new(
            ObservationId::new(2),
            BackendSource::Npcap,
            now,
            now,
            Direction::Unknown,
            "1",
            Packet::new(bytes),
        );
        let mut table = flow_engine::FlowTable::with_defaults(16).unwrap();
        let result = process_observation_legacy(observation, &mut table).unwrap();
        assert_eq!(result.parsed.protocol, NetworkProtocol::Arp);
        assert!(result.flow_key.is_none());
        assert_eq!(table.len(), 0);
    }
}