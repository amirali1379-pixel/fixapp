// Capture pipeline — native backend -> Host-controlled action -> PacketObservation -> PacketBus.
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use backend_windivert::{InterceptedPacket, WinDivertBackend, WinDivertConfig, WinDivertLayer};
use network_core::observation::{NativeCaptureContext, PacketObservation};
use network_core::timestamp::Timestamp;
use network_core::{BackendSource, Direction, EngineError, EngineErrorCode, EngineResult};
use packet_parser::ParsedPacket;

use crate::decision::{evaluate_packet, PacketDecision};
use crate::engine::{global_engine, EngineRuntime};

const CAPTURE_IDLE_SLEEP: Duration = Duration::from_millis(1);

impl EngineRuntime {
    pub fn ingest_observation(&self, mut observation: PacketObservation) -> EngineResult<()> {
        self.require_running()?;
        observation.ingestion_timestamp = Timestamp::now();
        if observation.packet.is_empty() {
            return Err(EngineError::with_message(EngineErrorCode::InvalidArgument, "observation carries an empty packet"));
        }
        if observation.packet_length != observation.packet.len() {
            return Err(EngineError::with_message(EngineErrorCode::InvalidArgument, "observation packet_length does not match packet bytes"));
        }
        let byte_count = observation.packet_length.min(u64::MAX as usize) as u64;
        match self.packet_bus.publish_engine_owned(observation) {
            Ok(()) => {
                self.statistics.total_packets_received.fetch_add(1, Ordering::Relaxed);
                self.statistics.total_bytes_received.fetch_add(byte_count, Ordering::Relaxed);
                Ok(())
            }
            Err(error) => {
                if error.code() == EngineErrorCode::QueueFull {
                    self.statistics.queue_saturation_events.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.statistics.total_errors.fetch_add(1, Ordering::Relaxed);
                }
                Err(error)
            }
        }
    }

    pub fn ingest_windivert_packet(&self, observation_id: u64, packet: InterceptedPacket) -> EngineResult<()> {
        let direction = match packet.direction {
            backend_windivert::PacketDirection::Inbound => Direction::Inbound,
            backend_windivert::PacketDirection::Outbound => Direction::Outbound,
        };
        let address = packet.address();
        let interface_identity = address.interface_index().to_string();
        let native_context = NativeCaptureContext { backend: BackendSource::WinDivert, bytes: address.to_bytes().to_vec() };
        let observation = PacketObservation::new(
            network_core::ObservationId::new(observation_id),
            BackendSource::WinDivert,
            Timestamp::now(),
            Timestamp::now(),
            direction,
            interface_identity,
            network_core::Packet::new(packet.data),
        )
        .with_native_context(native_context)
        .with_native_metadata("layer", address.layer().to_string())
        .with_native_metadata("loopback", address.is_loopback().to_string())
        .with_native_metadata("impostor", address.is_impostor().to_string())
        .with_provenance("backend-windivert");
        self.ingest_observation(observation)
    }

    pub fn capture_start(&self) -> EngineResult<()> {
        self.require_running()?;
        let mut guard = self.capture_thread.lock().map_err(|_| EngineError::with_message(EngineErrorCode::InternalError, "capture thread handle mutex poisoned"))?;
        if guard.is_some() { return Ok(()); }
        let backend_name = self.active_capture_backend()?.unwrap_or_else(|| "windivert".to_string());
        if backend_name != "windivert" {
            return Err(EngineError::with_message(EngineErrorCode::CapabilityUnavailable, format!("capture backend '{}' has no connected Engine capture worker", backend_name)));
        }
        let config = WinDivertConfig::new("true", WinDivertLayer::Network).map_err(|_| EngineError::backend_init_failed())?;
        let mut backend = WinDivertBackend::new(config);
        backend.start().map_err(|error| EngineError::with_message(EngineErrorCode::BackendStartFailed, format!("WinDivert capture handle failed to open: {:?}", error)))?;

        // The live capture worker owns the Host-controlled action point. When
        // WinDivert is the capture backend, its send-only action handle is the
        // concrete reinjection path for Pass/Inspect decisions.
        if self.active_reinjection_backend()?.is_none() {
            self.set_active_reinjection_backend(Some("windivert".to_string()))?;
        }

        self.capture_stop.store(false, Ordering::SeqCst);
        let stop = Arc::clone(&self.capture_stop);
        let state = Arc::clone(&self.state);
        let packet_bus = Arc::clone(&self.packet_bus);
        let statistics = Arc::clone(&self.statistics);
        let next_id = Arc::new(std::sync::atomic::AtomicU64::new(1));
        let handle = std::thread::Builder::new().name("network-engine-capture".into())
            .spawn(move || capture_worker_loop(backend, stop, state, packet_bus, statistics, next_id))
            .map_err(|_| EngineError::with_message(EngineErrorCode::InternalError, "failed to spawn capture worker"))?;
        *guard = Some(handle);
        Ok(())
    }

    pub fn capture_stop(&self) -> EngineResult<()> {
        self.capture_stop.store(true, Ordering::SeqCst);
        let mut guard = self.capture_thread.lock().map_err(|_| EngineError::with_message(EngineErrorCode::InternalError, "capture thread handle mutex poisoned"))?;
        if let Some(handle) = guard.take() { let _ = handle.join(); }
        Ok(())
    }
}

fn capture_worker_loop(
    mut backend: WinDivertBackend,
    stop: Arc<std::sync::atomic::AtomicBool>,
    state: Arc<network_core::EngineState>,
    packet_bus: Arc<packet_bus::PacketBus>,
    statistics: Arc<network_core::statistics::EngineStatistics>,
    next_id: Arc<std::sync::atomic::AtomicU64>,
) {
    while !stop.load(Ordering::SeqCst) && !state.is_shutdown_requested() {
        match backend.recv() {
            Ok(packet) => {
                let id = next_id.fetch_add(1, Ordering::Relaxed);
                let packet_len = packet.data.len() as u64;
                let direction = match packet.direction {
                    backend_windivert::PacketDirection::Inbound => Direction::Inbound,
                    backend_windivert::PacketDirection::Outbound => Direction::Outbound,
                };
                let address = packet.address();
                let native_context = NativeCaptureContext {
                    backend: BackendSource::WinDivert,
                    bytes: address.to_bytes().to_vec(),
                };
                let observation = PacketObservation::new(
                    network_core::ObservationId::new(id),
                    BackendSource::WinDivert,
                    Timestamp::now(),
                    Timestamp::now(),
                    direction,
                    address.interface_index().to_string(),
                    network_core::Packet::new(packet.data),
                )
                .with_native_context(native_context)
                .with_native_metadata("layer", address.layer().to_string())
                .with_native_metadata("loopback", address.is_loopback().to_string())
                .with_native_metadata("impostor", address.is_impostor().to_string())
                .with_provenance("backend-windivert");

                let decision = match ParsedPacket::parse(&observation) {
                    Ok(parsed) => {
                        let policy = match global_engine().lock() {
                            Ok(guard) => match guard.as_ref() {
                                Some(engine) => match engine.packet_policy() {
                                    Ok(policy) => policy,
                                    Err(_) => {
                                        statistics.total_errors.fetch_add(1, Ordering::Relaxed);
                                        continue;
                                    }
                                },
                                None => {
                                    statistics.total_errors.fetch_add(1, Ordering::Relaxed);
                                    continue;
                                }
                            },
                            Err(_) => {
                                statistics.total_errors.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                        };
                        evaluate_packet(&parsed, direction, &policy)
                    }
                    Err(_) => PacketDecision::Pass,
                };

                // The action is applied before the observation is handed to
                // the rest of the engine. This closes the previous gap where
                // policy was only stored/advisory and the intercepted packet
                // was released without a native action.
                let action_result = match decision {
                    PacketDecision::Drop => Ok(()),
                    PacketDecision::Pass | PacketDecision::Inspect => {
                        let context = observation.native_context.as_ref().map(|c| c.bytes.as_slice());
                        match context {
                            Some(context) => match global_engine().lock() {
                                Ok(guard) => match guard.as_ref() {
                                    Some(engine) => engine.windivert_reinject(observation.packet.as_slice(), context),
                                    None => Err(EngineError::with_message(EngineErrorCode::NotInitialized, "engine is not initialized")),
                                },
                                Err(_) => Err(EngineError::with_message(EngineErrorCode::InternalError, "engine mutex poisoned")),
                            },
                            None => Err(EngineError::with_message(EngineErrorCode::ActionFailed, "WinDivert native context is unavailable")),
                        }
                    }
                };

                if action_result.is_err() {
                    statistics.total_errors.fetch_add(1, Ordering::Relaxed);
                    std::thread::sleep(CAPTURE_IDLE_SLEEP);
                    continue;
                }

                match packet_bus.publish_engine_owned(observation) {
                    Ok(()) => {
                        statistics.total_packets_received.fetch_add(1, Ordering::Relaxed);
                        statistics.total_bytes_received.fetch_add(packet_len, Ordering::Relaxed);
                    }
                    Err(error) => {
                        if error.code() == EngineErrorCode::QueueFull {
                            statistics.queue_saturation_events.fetch_add(1, Ordering::Relaxed);
                        } else {
                            statistics.total_errors.fetch_add(1, Ordering::Relaxed);
                        }
                        std::thread::sleep(CAPTURE_IDLE_SLEEP);
                    }
                }
            }
            Err(_) => {
                if stop.load(Ordering::SeqCst) || state.is_shutdown_requested() { break; }
                std::thread::sleep(CAPTURE_IDLE_SLEEP);
            }
        }
    }
    let _ = backend.stop();
}
