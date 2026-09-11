pub mod adapter;
pub mod capture;
pub mod device;
pub mod ffi;
pub mod metadata;

pub use adapter::{
    AdapterAddress,
    AdapterInfo,
    AdapterState,
    AdapterTable,
    AdapterTableError,
    AdapterType,
};

pub use capture::{
    CaptureConfig,
    CaptureDirection,
    CaptureError,
    CaptureSession,
    CaptureState,
    CapturedPacket,
};

pub use device::{
    DeviceError,
    DeviceManager,
    DeviceState,
    NpcapDevice,
    normalize_device_name,
};

pub use metadata::{
    AdapterMetadata,
    LinkType,
    PacketDirection,
    PacketMetadata,
    MetadataTable,
};

use network_core::{
    BackendSource,
    Direction,
    ObservationId,
    OwnershipState,
    OwnershipTracker,
    PacketObservation,
    Timestamp,
};

use std::sync::atomic::{
    AtomicU64,
    Ordering,
};

/// Npcap backend lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NpcapBackendState {
    Disabled,
    Starting,
    Running,
    Degraded,
    Failed,
    Stopping,
    Stopped,
}

/// Npcap backend errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NpcapError {
    AlreadyRunning,
    NotRunning,
    InitializationFailed,
    DeviceUnavailable,
    CaptureFailed,
    InvalidCaptureId,
    ObservationCreationFailed,
}

/// Npcap backend.
///
/// Owns Npcap capture sessions and converts captured packets into the
/// authoritative network-core PacketObservation contract.
///
/// Runtime ownership flow:
///
/// ```text
/// Allocated
///     ↓
/// BackendOwned
///     ↓
/// EngineOwned
///     ↓
/// PacketBus
/// ```
///
/// The transition to BusOwned is intentionally performed by the
/// PacketBus integration after a successful publish.
#[derive(Debug)]
pub struct NpcapBackend {
    state: NpcapBackendState,
    devices: DeviceManager,
    adapters: AdapterTable,
    metadata: MetadataTable,
    captures: Vec<CaptureSession>,

    /// Process-local observation ID generator.
    next_observation_id: AtomicU64,
}

impl NpcapBackend {
    pub fn new() -> Self {
        Self {
            state: NpcapBackendState::Stopped,
            devices: DeviceManager::new(),
            adapters: AdapterTable::new(),
            metadata: MetadataTable::new(),
            captures: Vec::new(),
            next_observation_id: AtomicU64::new(1),
        }
    }

    pub fn start(
        &mut self,
    ) -> Result<(), NpcapError> {
        if self.state == NpcapBackendState::Running {
            return Err(NpcapError::AlreadyRunning);
        }

        self.state = NpcapBackendState::Starting;

        // Native Npcap device discovery/opening remains in the
        // device/ffi layers. This backend owns their lifecycle.
        self.state = NpcapBackendState::Running;

        Ok(())
    }

    pub fn stop(
        &mut self,
    ) -> Result<(), NpcapError> {
        if self.state != NpcapBackendState::Running
            && self.state != NpcapBackendState::Degraded
        {
            return Err(NpcapError::NotRunning);
        }

        self.state = NpcapBackendState::Stopping;

        for capture in &mut self.captures {
            if capture.is_running() {
                let _ = capture.stop();
            }
        }

        self.state = NpcapBackendState::Stopped;

        Ok(())
    }

    pub fn state(
        &self,
    ) -> NpcapBackendState {
        self.state
    }

    pub fn is_running(
        &self,
    ) -> bool {
        self.state == NpcapBackendState::Running
    }

    pub fn degrade(&mut self) {
        if self.is_running() {
            self.state = NpcapBackendState::Degraded;
        }
    }

    pub fn fail(&mut self) {
        self.state = NpcapBackendState::Failed;
    }

    pub fn devices(
        &self,
    ) -> &DeviceManager {
        &self.devices
    }

    pub fn devices_mut(
        &mut self,
    ) -> &mut DeviceManager {
        &mut self.devices
    }

    pub fn adapters(
        &self,
    ) -> &AdapterTable {
        &self.adapters
    }

    pub fn adapters_mut(
        &mut self,
    ) -> &mut AdapterTable {
        &mut self.adapters
    }

    pub fn metadata(
        &self,
    ) -> &MetadataTable {
        &self.metadata
    }

    pub fn metadata_mut(
        &mut self,
    ) -> &mut MetadataTable {
        &mut self.metadata
    }

    pub fn captures(
        &self,
    ) -> &[CaptureSession] {
        &self.captures
    }

    pub fn create_capture(
        &mut self,
        config: CaptureConfig,
    ) -> Result<usize, NpcapError> {
        if !self.is_running() {
            return Err(NpcapError::NotRunning);
        }

        let session = CaptureSession::new(config)
            .map_err(|_| NpcapError::CaptureFailed)?;

        self.captures.push(session);

        Ok(self.captures.len() - 1)
    }

    pub fn start_capture(
        &mut self,
        capture_id: usize,
    ) -> Result<(), NpcapError> {
        if !self.is_running() {
            return Err(NpcapError::NotRunning);
        }

        let interface_index = self
            .captures
            .get(capture_id)
            .ok_or(NpcapError::InvalidCaptureId)?
            .config()
            .interface_index;

        let device_name = self
            .adapters
            .get(interface_index)
            .map(|adapter| adapter.name.clone())
            .map_err(|_| NpcapError::DeviceUnavailable)?;

        let capture = self
            .captures
            .get_mut(capture_id)
            .ok_or(NpcapError::InvalidCaptureId)?;

        capture
            .start(&device_name)
            .map_err(|_| NpcapError::CaptureFailed)
    }

    pub fn stop_capture(
        &mut self,
        capture_id: usize,
    ) -> Result<(), NpcapError> {
        let capture = self
            .captures
            .get_mut(capture_id)
            .ok_or(NpcapError::InvalidCaptureId)?;

        capture
            .stop()
            .map_err(|_| NpcapError::CaptureFailed)
    }

    /// Receives one packet from an active capture session.
    ///
    /// `Ok(None)` represents the native capture timeout and is not a
    /// backend failure. This preserves the lower-level Npcap capture
    /// contract instead of converting a normal timeout into an error.
    pub fn receive_packet(
        &mut self,
        capture_id: usize,
    ) -> Result<Option<CapturedPacket>, NpcapError> {
        if !self.is_running()
            && self.state != NpcapBackendState::Degraded
        {
            return Err(NpcapError::NotRunning);
        }

        let capture = self
            .captures
            .get_mut(capture_id)
            .ok_or(NpcapError::InvalidCaptureId)?;

        if !capture.is_running() {
            return Err(NpcapError::CaptureFailed);
        }

        capture
            .receive_packet()
            .map_err(|_| NpcapError::CaptureFailed)
    }

    /// Converts one captured Npcap packet into the authoritative
    /// PacketObservation contract.
    ///
    /// Ownership:
    ///
    /// ```text
    /// Allocated → BackendOwned → EngineOwned
    /// ```
    ///
    /// The returned tracker is intentionally still EngineOwned.
    /// PacketBus integration must perform EngineOwned → BusOwned only
    /// after successful queue publication.
    pub fn receive_observation(
        &mut self,
        capture_id: usize,
    ) -> Result<
        (PacketObservation, OwnershipTracker),
        NpcapError,
    > {
        let captured = self
            .receive_packet(capture_id)?
            .ok_or(NpcapError::CaptureFailed)?;

        let interface_index = captured.interface_index;

        let interface_identity = self
            .adapters
            .get(interface_index)
            .map(|adapter| adapter.name.clone())
            .unwrap_or_else(|_| {
                format!("npcap:{}", interface_index)
            });

        let capture_timestamp = Timestamp::now();
        let packet = network_core::Packet::new(
            captured.data,
        );

        if packet.is_empty() {
            return Err(NpcapError::ObservationCreationFailed);
        }

        let ingestion_timestamp = Timestamp::now();

        let observation_id = ObservationId::new(
            self.next_observation_id
                .fetch_add(1, Ordering::Relaxed),
        );

        let observation = PacketObservation::new(
            observation_id,
            BackendSource::Npcap,
            capture_timestamp,
            ingestion_timestamp,
            Direction::Unknown,
            interface_identity,
            packet,
        )
        .with_native_metadata(
            "backend",
            "npcap",
        )
        .with_native_metadata(
            "interface_index",
            interface_index.to_string(),
        )
        .with_native_metadata(
            "original_length",
            captured.original_length.to_string(),
        )
        .with_provenance(
            "captured-by-npcap",
        );

        let mut ownership = OwnershipTracker::new();

        ownership
            .transition(OwnershipState::BackendOwned)
            .map_err(|_| NpcapError::ObservationCreationFailed)?;

        ownership
            .handoff_backend_to_engine()
            .map_err(|_| NpcapError::ObservationCreationFailed)?;

        Ok((observation, ownership))
    }

    /// Returns the next observation identifier without creating
    /// an observation.
    pub fn next_observation_id(
        &self,
    ) -> ObservationId {
        ObservationId::new(
            self.next_observation_id
                .load(Ordering::Relaxed),
        )
    }

    pub fn clear_runtime_state(
        &mut self,
    ) {
        self.captures.clear();
        self.metadata.clear();
        self.adapters.clear();
        self.devices.clear();

        self.next_observation_id
            .store(1, Ordering::Relaxed);
    }
}

impl Default for NpcapBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for NpcapBackend {
    fn drop(&mut self) {
        for capture in &mut self.captures {
            if capture.is_running() {
                let _ = capture.stop();
            }
        }

        self.state = NpcapBackendState::Stopped;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_starts() {
        let mut backend = NpcapBackend::new();

        assert_eq!(
            backend.state(),
            NpcapBackendState::Stopped
        );

        backend.start().unwrap();

        assert!(backend.is_running());
    }

    #[test]
    fn backend_cannot_start_twice() {
        let mut backend = NpcapBackend::new();

        backend.start().unwrap();

        assert_eq!(
            backend.start(),
            Err(NpcapError::AlreadyRunning)
        );
    }

    #[test]
    fn backend_stops() {
        let mut backend = NpcapBackend::new();

        backend.start().unwrap();
        backend.stop().unwrap();

        assert_eq!(
            backend.state(),
            NpcapBackendState::Stopped
        );
    }

    #[test]
    fn capture_requires_running_backend() {
        let mut backend = NpcapBackend::new();

        let config = CaptureConfig::new(1).unwrap();

        assert_eq!(
            backend.create_capture(config),
            Err(NpcapError::NotRunning)
        );
    }

    #[test]
    fn backend_can_create_capture() {
        let mut backend = NpcapBackend::new();

        backend.start().unwrap();

        let config = CaptureConfig::new(1).unwrap();

        let capture = backend
            .create_capture(config)
            .unwrap();

        assert_eq!(capture, 0);
        assert_eq!(backend.captures().len(), 1);
    }

    #[test]
    fn capture_can_be_started() {
        let mut backend = NpcapBackend::new();

        backend.start().unwrap();

        backend
            .adapters_mut()
            .insert(
                AdapterInfo::new(
                    1,
                    "test-device",
                )
                .unwrap(),
            )
            .unwrap();

        let config = CaptureConfig::new(1).unwrap();

        let capture = backend
            .create_capture(config)
            .unwrap();

        backend
            .start_capture(capture)
            .unwrap();

        assert!(
            backend
                .captures()[capture]
                .is_running()
        );
    }

    #[test]
    fn start_capture_requires_known_adapter() {
        let mut backend = NpcapBackend::new();

        backend.start().unwrap();

        let config = CaptureConfig::new(1).unwrap();

        let capture = backend
            .create_capture(config)
            .unwrap();

        assert_eq!(
            backend.start_capture(capture),
            Err(NpcapError::DeviceUnavailable)
        );
    }

    #[test]
    fn invalid_capture_id_is_rejected() {
        let mut backend = NpcapBackend::new();

        backend.start().unwrap();

        assert_eq!(
            backend.start_capture(999),
            Err(NpcapError::InvalidCaptureId)
        );
    }

    #[test]
    fn receive_packet_requires_running_backend() {
        let mut backend = NpcapBackend::new();

        assert_eq!(
            backend.receive_packet(0),
            Err(NpcapError::NotRunning)
        );
    }

    #[test]
    fn receive_observation_requires_valid_capture() {
        let mut backend = NpcapBackend::new();

        backend.start().unwrap();

        assert_eq!(
            backend.receive_observation(999),
            Err(NpcapError::InvalidCaptureId)
        );
    }

    #[test]
    fn observation_id_starts_at_one() {
        let backend = NpcapBackend::new();

        assert_eq!(
            backend.next_observation_id().as_u64(),
            1
        );
    }

    #[test]
    fn clear_runtime_state_works() {
        let mut backend = NpcapBackend::new();

        backend.start().unwrap();

        let config = CaptureConfig::new(1).unwrap();

        backend
            .create_capture(config)
            .unwrap();

        backend.clear_runtime_state();

        assert_eq!(backend.captures().len(), 0);
        assert_eq!(backend.devices().len(), 0);
        assert_eq!(backend.adapters().len(), 0);
    }

    #[test]
    fn backend_can_degrade() {
        let mut backend = NpcapBackend::new();

        backend.start().unwrap();
        backend.degrade();

        assert_eq!(
            backend.state(),
            NpcapBackendState::Degraded
        );
    }

    #[test]
    fn observation_backend_source_is_npcap() {
        let backend = NpcapBackend::new();

        assert_eq!(
            BackendSource::Npcap,
            BackendSource::Npcap
        );
    }
}