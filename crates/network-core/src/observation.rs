use crate::packet::Packet;
use crate::timestamp::Timestamp;

/// Unique identifier for a packet observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObservationId(pub u64);

impl ObservationId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

/// Backend source identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackendSource {
    Wfp,
    WinDivert,
    Npcap,
    IpHelper,
    Etw,
    Unknown,
}

/// Packet direction relative to the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    Inbound,
    Outbound,
    Unknown,
}

/// Backend-owned opaque context required to complete a native packet action.
/// The Engine owns the observation; the bytes are interpreted only by the
/// backend that produced them. This keeps backend-native types out of core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeCaptureContext {
    pub backend: BackendSource,
    pub bytes: Vec<u8>,
}

/// Lightweight packet observation from a backend.
///
/// Creation must remain lightweight. The observation wraps the
/// authoritative packet and adds provenance/context without
/// modifying the original data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketObservation {
    /// Unique observation identifier.
    pub observation_id: ObservationId,

    /// Which backend produced this observation.
    pub backend_source: BackendSource,

    /// Timestamp from the backend capture point.
    pub capture_timestamp: Timestamp,

    /// Timestamp when the observation entered the engine.
    pub ingestion_timestamp: Timestamp,

    /// Packet direction.
    pub direction: Direction,

    /// Interface identity (opaque string).
    pub interface_identity: String,

    /// Packet length in bytes.
    pub packet_length: usize,

    /// The authoritative packet data.
    pub packet: Packet,

    /// Native metadata from the backend (normalized to string key-value pairs).
    pub native_metadata: Vec<(String, String)>,

    /// Opaque native capture context retained for a later backend action.
    /// The core never interprets backend-specific layout.
    pub native_context: Option<NativeCaptureContext>,

    /// Provenance and context information.
    pub provenance: Vec<String>,
}

impl PacketObservation {
    /// Creates a new lightweight packet observation.
    ///
    /// Both timestamps should be provided by the caller. The ingestion
    /// timestamp is typically captured at the moment this struct is
    /// constructed.
    pub fn new(
        observation_id: ObservationId,
        backend_source: BackendSource,
        capture_timestamp: Timestamp,
        ingestion_timestamp: Timestamp,
        direction: Direction,
        interface_identity: impl Into<String>,
        packet: Packet,
    ) -> Self {
        Self {
            observation_id,
            backend_source,
            capture_timestamp,
            ingestion_timestamp,
            direction,
            interface_identity: interface_identity.into(),
            packet_length: packet.len(),
            packet,
            native_metadata: Vec::new(),
            native_context: None,
            provenance: Vec::new(),
        }
    }

    /// Adds a native metadata field.
    pub fn with_native_metadata(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.native_metadata.push((key.into(), value.into()));
        self
    }

    /// Attaches opaque backend-native capture context.
    pub fn with_native_context(
        mut self,
        context: NativeCaptureContext,
    ) -> Self {
        self.native_context = Some(context);
        self
    }

    /// Adds a provenance entry.
    pub fn with_provenance(
        mut self,
        entry: impl Into<String>,
    ) -> Self {
        self.provenance.push(entry.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observation_creation_is_lightweight() {
        let packet = Packet::new(vec![0x45, 0x00, 0x00, 0x28]);
        let now = Timestamp::now();

        let obs = PacketObservation::new(
            ObservationId::new(1),
            BackendSource::WinDivert,
            now,
            now,
            Direction::Inbound,
            "eth0",
            packet,
        );

        assert_eq!(obs.observation_id.as_u64(), 1);
        assert_eq!(obs.backend_source, BackendSource::WinDivert);
        assert_eq!(obs.direction, Direction::Inbound);
        assert_eq!(obs.interface_identity, "eth0");
        assert_eq!(obs.packet_length, 4);
        assert_eq!(obs.packet.as_slice(), &[0x45, 0x00, 0x00, 0x28]);
        assert!(obs.native_context.is_none());
    }

    #[test]
    fn observation_has_all_directions() {
        let packet = Packet::new(vec![1]);
        let now = Timestamp::now();

        let inbound = PacketObservation::new(
            ObservationId::new(1),
            BackendSource::Wfp,
            now,
            now,
            Direction::Inbound,
            "if1",
            packet.clone(),
        );

        let outbound = PacketObservation::new(
            ObservationId::new(2),
            BackendSource::Wfp,
            now,
            now,
            Direction::Outbound,
            "if1",
            packet.clone(),
        );

        let unknown = PacketObservation::new(
            ObservationId::new(3),
            BackendSource::Npcap,
            now,
            now,
            Direction::Unknown,
            "if2",
            packet,
        );

        assert_eq!(inbound.direction, Direction::Inbound);
        assert_eq!(outbound.direction, Direction::Outbound);
        assert_eq!(unknown.direction, Direction::Unknown);
    }

    #[test]
    fn observation_preserves_packet_authority() {
        let packet = Packet::new(vec![0xAA, 0xBB, 0xCC]);
        let now = Timestamp::now();

        let obs = PacketObservation::new(
            ObservationId::new(1),
            BackendSource::WinDivert,
            now,
            now,
            Direction::Inbound,
            "eth0",
            packet,
        )
        .with_native_metadata("layer", "3")
        .with_provenance("captured-by-windivert");

        assert_eq!(obs.packet.as_slice(), &[0xAA, 0xBB, 0xCC]);
        assert_eq!(obs.native_metadata.len(), 1);
        assert_eq!(obs.provenance.len(), 1);
    }

    #[test]
    fn native_context_is_preserved_without_backend_type_leakage() {
        let now = Timestamp::now();
        let context = NativeCaptureContext {
            backend: BackendSource::WinDivert,
            bytes: vec![9; 80],
        };

        let obs = PacketObservation::new(
            ObservationId::new(7),
            BackendSource::WinDivert,
            now,
            now,
            Direction::Outbound,
            "7",
            Packet::new(vec![1, 2, 3]),
        )
        .with_native_context(context);

        assert_eq!(obs.native_context.as_ref().unwrap().bytes.len(), 80);
        assert_eq!(
            obs.native_context.as_ref().unwrap().backend,
            BackendSource::WinDivert
        );
    }
}