use std::collections::HashMap;
use backend_npcap::{AdapterInfo, CaptureConfig, NpcapBackend, NpcapError};
use backend_windivert::{WinDivertBackend, WinDivertConfig, WinDivertError, WinDivertLayer};
use network_core::{BackendSource, Direction, EngineError, EngineErrorCode, ObservationId, OwnershipState, OwnershipTracker, PacketObservation, Timestamp};
use packet_bus::PacketBus;
use crate::decision::PacketDecision;

#[derive(Debug)]
pub enum CaptureRuntime {
    WinDivert { backend: WinDivertBackend, next_observation_id: u64, pending_addresses: HashMap<u64, backend_windivert::ffi::WinDivertAddress> },
    Npcap { backend: NpcapBackend, capture_id: usize, next_observation_id: u64 },
}

impl CaptureRuntime {
    pub fn start(backend_name: &str) -> Result<Self, EngineError> {
        match backend_name {
            "windivert" => Self::start_windivert(),
            "npcap" => Err(EngineError::with_message(EngineErrorCode::BackendUnavailable, "Npcap capture requires an explicit Windows interface index and native device name")),
            _ => Err(EngineError::with_message(EngineErrorCode::BackendUnavailable, format!("native capture runtime is not configured for backend '{}'", backend_name))),
        }
    }

    fn start_windivert() -> Result<Self, EngineError> {
        let config = WinDivertConfig::new("true", WinDivertLayer::Network).map_err(|_| EngineError::with_message(EngineErrorCode::BackendStartFailed, "invalid WinDivert configuration"))?;
        let mut backend = WinDivertBackend::new(config);
        backend.start().map_err(map_windivert_start_error)?;
        Ok(Self::WinDivert { backend, next_observation_id: 1, pending_addresses: HashMap::new() })
    }

    pub fn start_npcap(interface_index: u32, device_name: &str) -> Result<Self, EngineError> {
        if interface_index == 0 || device_name.trim().is_empty() {
            return Err(EngineError::with_message(EngineErrorCode::InvalidArgument, "Npcap requires a non-zero interface index and non-empty device name"));
        }
        let mut backend = NpcapBackend::new();
        backend.start().map_err(map_npcap_start_error)?;
        let adapter = AdapterInfo::new(interface_index, device_name).ok_or_else(|| EngineError::with_message(EngineErrorCode::InvalidArgument, "invalid Npcap adapter identity"))?;
        backend.adapters_mut().insert(adapter).map_err(|_| EngineError::with_message(EngineErrorCode::InvalidArgument, "failed to register Npcap adapter"))?;
        let config = CaptureConfig::new(interface_index).ok_or_else(|| EngineError::with_message(EngineErrorCode::InvalidArgument, "invalid Npcap interface index"))?;
        let capture_id = backend.create_capture(config).map_err(map_npcap_capture_error)?;
        if let Err(error) = backend.start_capture(capture_id) {
            let _ = backend.stop();
            return Err(map_npcap_capture_error(error));
        }
        Ok(Self::Npcap { backend, capture_id, next_observation_id: 1 })
    }

    pub fn backend_name(&self) -> &'static str {
        match self { Self::WinDivert { .. } => "windivert", Self::Npcap { .. } => "npcap" }
    }

    pub fn poll(&mut self, bus: &PacketBus) -> Result<(), EngineError> {
        match self {
            Self::WinDivert { backend, next_observation_id, pending_addresses } => {
                // Native action context is bounded by the PacketBus capacity.
                // Never receive another intercepted packet while all action
                // contexts are waiting for the processing stage.
                if pending_addresses.len() >= bus.capacity() {
                    return Err(EngineError::queue_full());
                }
                let intercepted = backend.recv().map_err(map_windivert_receive_error)?;
                let direction = match intercepted.direction { backend_windivert::PacketDirection::Inbound => Direction::Inbound, backend_windivert::PacketDirection::Outbound => Direction::Outbound };
                let observation_id = ObservationId::new(*next_observation_id);
                *next_observation_id = next_observation_id.saturating_add(1);
                let native_address = intercepted.address();
                let interface_index = intercepted.interface_index;
                let loopback = intercepted.loopback;
                let impostor = intercepted.impostor;
                let packet = network_core::Packet::new(intercepted.data);
                if packet.is_empty() { return Err(EngineError::with_message(EngineErrorCode::InvalidArgument, "native backend returned an empty packet")); }
                let observation = PacketObservation::new(observation_id, BackendSource::WinDivert, Timestamp::now(), Timestamp::now(), direction, interface_index.to_string(), packet)
                    .with_native_metadata("interface_index", interface_index.to_string())
                    .with_native_metadata("loopback", loopback.to_string())
                    .with_native_metadata("impostor", impostor.to_string())
                    .with_provenance("captured-by-windivert");
                publish_engine_owned(bus, observation)?;
                pending_addresses.insert(observation_id.as_u64(), native_address);
                Ok(())
            }
            Self::Npcap { backend, capture_id, next_observation_id } => {
                let captured = backend.receive_packet(*capture_id).map_err(map_npcap_capture_error)?;
                let Some(captured) = captured else { return Ok(()); };
                let packet = network_core::Packet::new(captured.data);
                if packet.is_empty() { return Err(EngineError::with_message(EngineErrorCode::InvalidArgument, "Npcap returned an empty packet")); }
                let observation_id = ObservationId::new(*next_observation_id);
                *next_observation_id = next_observation_id.saturating_add(1);
                let observation = PacketObservation::new(observation_id, BackendSource::Npcap, Timestamp::now(), Timestamp::now(), Direction::Unknown, captured.interface_index.to_string(), packet)
                    .with_native_metadata("backend", "npcap")
                    .with_native_metadata("interface_index", captured.interface_index.to_string())
                    .with_native_metadata("original_length", captured.original_length.to_string())
                    .with_provenance("captured-by-npcap");
                publish_engine_owned(bus, observation)
            }
        }
    }

    pub fn execute_decision(&mut self, observation_id: ObservationId, decision: PacketDecision, raw_packet: &[u8]) -> Result<(), EngineError> {
        let Self::WinDivert { backend, pending_addresses, .. } = self else {
            return Err(EngineError::with_message(EngineErrorCode::ActionNotSupported, "selected capture backend does not support packet actions"));
        };
        let key = observation_id.as_u64();
        match decision {
            PacketDecision::Pass | PacketDecision::Inspect => {
                let address = pending_addresses.get(&key).ok_or_else(|| EngineError::with_message(EngineErrorCode::ActionFailed, "native action context for observation is unavailable"))?;
                backend.reinject(raw_packet, address).map_err(map_windivert_action_error)?;
                pending_addresses.remove(&key);
                Ok(())
            }
            PacketDecision::Drop => {
                pending_addresses.remove(&key).ok_or_else(|| EngineError::with_message(EngineErrorCode::ActionFailed, "native action context for observation is unavailable"))?;
                Ok(())
            }
        }
    }

    pub fn stop(&mut self) -> Result<(), EngineError> {
        match self {
            Self::WinDivert { backend, pending_addresses, .. } => { pending_addresses.clear(); backend.stop().map_err(map_windivert_stop_error) }
            Self::Npcap { backend, .. } => match backend.state() {
                backend_npcap::NpcapBackendState::Running | backend_npcap::NpcapBackendState::Degraded => backend.stop().map_err(map_npcap_stop_error),
                _ => Ok(()),
            },
        }
    }
}

fn publish_engine_owned(bus: &PacketBus, observation: PacketObservation) -> Result<(), EngineError> {
    let mut ownership = OwnershipTracker::new();
    ownership.transition(OwnershipState::BackendOwned).map_err(|_| invalid_ownership())?;
    ownership.handoff_backend_to_engine().map_err(|_| invalid_ownership())?;
    match bus.publish_engine_owned(observation) {
        Ok(()) => { ownership.handoff_engine_to_bus().map_err(|_| invalid_ownership())?; Ok(()) }
        Err(error) => { let _ = ownership.release(); Err(error) }
    }
}

fn invalid_ownership() -> EngineError { EngineError::with_message(EngineErrorCode::InvalidStateTransition, "native capture ownership transition failed") }
fn map_windivert_start_error(error: WinDivertError) -> EngineError { EngineError::with_message(EngineErrorCode::BackendStartFailed, format!("WinDivert start failed: {:?}", error)) }
fn map_windivert_stop_error(error: WinDivertError) -> EngineError { EngineError::with_message(EngineErrorCode::BackendStopFailed, format!("WinDivert stop failed: {:?}", error)) }
fn map_windivert_receive_error(error: WinDivertError) -> EngineError { EngineError::with_message(EngineErrorCode::BackendDegraded, format!("WinDivert receive failed: {:?}", error)) }
fn map_windivert_action_error(error: WinDivertError) -> EngineError { EngineError::with_message(EngineErrorCode::ActionFailed, format!("WinDivert action failed: {:?}", error)) }
fn map_npcap_start_error(error: NpcapError) -> EngineError { EngineError::with_message(EngineErrorCode::BackendStartFailed, format!("Npcap start failed: {:?}", error)) }
fn map_npcap_stop_error(error: NpcapError) -> EngineError { EngineError::with_message(EngineErrorCode::BackendStopFailed, format!("Npcap stop failed: {:?}", error)) }
fn map_npcap_capture_error(error: NpcapError) -> EngineError { EngineError::with_message(EngineErrorCode::BackendDegraded, format!("Npcap capture failed: {:?}", error)) }

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn unsupported_runtime_backend_is_rejected() { let result = CaptureRuntime::start("unknown"); assert!(result.is_err()); assert_eq!(result.unwrap_err().code(), EngineErrorCode::BackendUnavailable); }
    #[test] fn npcap_requires_explicit_interface_identity() { let result = CaptureRuntime::start("npcap"); assert!(result.is_err()); assert_eq!(result.unwrap_err().code(), EngineErrorCode::BackendUnavailable); }
    #[test] fn npcap_rejects_zero_interface() { let result = CaptureRuntime::start_npcap(0, "device"); assert!(result.is_err()); assert_eq!(result.unwrap_err().code(), EngineErrorCode::InvalidArgument); }
    #[test] fn npcap_rejects_empty_device() { let result = CaptureRuntime::start_npcap(1, "   "); assert!(result.is_err()); assert_eq!(result.unwrap_err().code(), EngineErrorCode::InvalidArgument); }
}
