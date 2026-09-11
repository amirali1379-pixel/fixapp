use network_core::observation::PacketObservation;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObservationIdentity {
    pub id: u64,
    pub source_hash: u64,
}

impl ObservationIdentity {
    pub fn from_observation(obs: &PacketObservation) -> Self {
        let mut hasher = DefaultHasher::new();
        obs.capture_timestamp.as_nanos().hash(&mut hasher);
        obs.packet_length.hash(&mut hasher);
        obs.packet.as_slice().hash(&mut hasher);
        Self {
            id: obs.observation_id.as_u64(),
            source_hash: hasher.finish(),
        }
    }
}
