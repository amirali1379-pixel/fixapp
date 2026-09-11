use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use network_core::{
    error::EngineError,
    observation::{ObservationId, PacketObservation},
};

use crate::{
    buffer::PacketBuffer,
    ownership::{Owner, OwnershipTracker},
    queue::{ObservationQueue, QueueError},
};

#[derive(Debug)]
pub struct PacketBus {
    queue: Arc<ObservationQueue>,
    ownership: Arc<Mutex<HashMap<ObservationId, OwnershipTracker>>>,
}

impl PacketBus {
    pub fn new(capacity: usize) -> Self {
        Self {
            queue: Arc::new(ObservationQueue::new(capacity)),
            ownership: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn capacity(&self) -> usize { self.queue.capacity() }
    pub fn len(&self) -> usize { self.queue.len() }
    pub fn is_empty(&self) -> bool { self.queue.is_empty() }
    pub fn is_full(&self) -> bool { self.queue.is_full() }

    /// Captured observations enter the authoritative lifecycle as:
    /// Allocated -> Backend -> Engine -> Bus.
    pub fn publish(&self, observation: PacketObservation) -> Result<(), EngineError> {
        self.publish_engine_owned(observation)
    }

    /// Publishes an observation while taking the ownership transition into
    /// the bus. The observation itself remains the authoritative packet data.
    pub fn publish_engine_owned(&self, observation: PacketObservation) -> Result<(), EngineError> {
        let id = observation.observation_id;
        let mut tracker = OwnershipTracker::default();
        tracker.allocated_to_backend()?;
        tracker.backend_to_engine()?;
        tracker.engine_to_bus()?;

        let mut ownership = self.ownership.lock().map_err(|_| {
            EngineError::with_message(
                network_core::EngineErrorCode::InternalError,
                "packet ownership mutex poisoned",
            )
        })?;
        if ownership.contains_key(&id) {
            return Err(EngineError::with_message(
                network_core::EngineErrorCode::InternalError,
                "duplicate observation ownership entry",
            ));
        }

        if let Err(error) = self.queue.try_enqueue(observation) {
            return Err(Self::map_queue_error(error));
        }

        ownership.insert(id, tracker);
        Ok(())
    }

    /// Returns the next observation and transfers Bus -> Processing.
    pub fn try_read(&self) -> Result<Option<PacketObservation>, EngineError> {
        match self.queue.try_dequeue() {
            Ok(Some(observation)) => {
                self.transfer(observation.observation_id, Owner::Bus, Owner::Processing)?;
                Ok(Some(observation))
            }
            Ok(None) => Ok(None),
            Err(QueueError::Closed) => Err(EngineError::shutdown_in_progress()),
            Err(QueueError::Full) => Err(EngineError::queue_full()),
        }
    }

    pub fn read(&self) -> Result<PacketObservation, EngineError> {
        let observation = self.queue.dequeue().map_err(Self::map_queue_error)?;
        self.transfer(observation.observation_id, Owner::Bus, Owner::Processing)?;
        Ok(observation)
    }

    pub fn try_read_into(&self, buffer: &mut PacketBuffer) -> Result<bool, EngineError> {
        if buffer.is_released() {
            return Err(EngineError::buffer_exhausted());
        }

        let Some(observation) = self.try_read()? else { return Ok(false); };
        let id = observation.observation_id;

        if observation.packet.as_slice().len() > buffer.capacity() {
            self.requeue_processing(observation)?;
            return Err(EngineError::buffer_exhausted());
        }

        if buffer.write(observation.packet.as_slice()).is_err() {
            let _ = self.requeue_processing(observation);
            return Err(EngineError::buffer_exhausted());
        }

        // This API copies the authoritative bytes into a caller buffer. The
        // observation is therefore returned to Engine ownership and released.
        self.transfer(id, Owner::Processing, Owner::Engine)?;
        self.release_engine_ownership(id)?;
        Ok(true)
    }

    /// Transfers Processing -> Engine -> Bus without creating a second
    /// ownership record. Used when a consumer cannot complete an operation.
    pub fn requeue_processing(&self, observation: PacketObservation) -> Result<(), EngineError> {
        let id = observation.observation_id;
        self.transfer(id, Owner::Processing, Owner::Engine)?;
        if let Err(error) = self.queue.try_enqueue(observation) {
            let _ = self.transfer(id, Owner::Engine, Owner::Processing);
            return Err(Self::map_queue_error(error));
        }
        self.transfer(id, Owner::Engine, Owner::Bus)
    }

    /// Transfers Processing -> Host for a public C ABI packet handle.
    pub fn transfer_to_host(&self, id: ObservationId) -> Result<(), EngineError> {
        self.transfer(id, Owner::Processing, Owner::Host)
    }

    /// Releases a Host-owned observation after the ABI handle is consumed.
    pub fn release_host(&self, id: ObservationId) -> Result<(), EngineError> {
        self.release_from(id, Owner::Host)
    }

    /// Releases an observation after internal processing has completed.
    pub fn release_processing(&self, id: ObservationId) -> Result<(), EngineError> {
        self.release_from(id, Owner::Processing)
    }

    fn release_engine_ownership(&self, id: ObservationId) -> Result<(), EngineError> {
        self.release_from(id, Owner::Engine)
    }

    fn release_from(&self, id: ObservationId, owner: Owner) -> Result<(), EngineError> {
        let mut ownership = self.ownership.lock().map_err(|_| {
            EngineError::with_message(
                network_core::EngineErrorCode::InternalError,
                "packet ownership mutex poisoned",
            )
        })?;
        let tracker = ownership.get(&id).ok_or_else(EngineError::invalid_handle)?;
        tracker.transfer(owner, Owner::Released)?;
        ownership.remove(&id);
        Ok(())
    }

    fn transfer(&self, id: ObservationId, expected: Owner, target: Owner) -> Result<(), EngineError> {
        let ownership = self.ownership.lock().map_err(|_| {
            EngineError::with_message(
                network_core::EngineErrorCode::InternalError,
                "packet ownership mutex poisoned",
            )
        })?;
        let tracker = ownership.get(&id).ok_or_else(EngineError::invalid_handle)?;
        tracker.transfer(expected, target)
    }

    pub fn close(&self) { self.queue.close(); }
    pub fn is_closed(&self) -> bool { self.queue.is_closed() }

    pub fn clear(&self) {
        self.queue.clear();
        if let Ok(mut ownership) = self.ownership.lock() {
            ownership.clear();
        }
    }

    #[inline]
    fn map_queue_error(error: QueueError) -> EngineError {
        match error {
            QueueError::Full => EngineError::queue_full(),
            QueueError::Closed => EngineError::shutdown_in_progress(),
        }
    }
}

impl Clone for PacketBus {
    fn clone(&self) -> Self {
        Self {
            queue: Arc::clone(&self.queue),
            ownership: Arc::clone(&self.ownership),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use network_core::{
        observation::{ObservationId, PacketObservation},
        packet::Packet,
        timestamp::Timestamp,
        BackendSource,
        Direction,
    };

    fn observation(id: u64) -> PacketObservation {
        let now = Timestamp::now();
        PacketObservation::new(
            ObservationId::new(id),
            BackendSource::WinDivert,
            now,
            now,
            Direction::Inbound,
            "eth0",
            Packet::new(vec![1, 2, 3, 4]),
        )
    }

    #[test]
    fn creates_empty_bus() {
        let bus = PacketBus::new(16);
        assert_eq!(bus.capacity(), 16);
        assert_eq!(bus.len(), 0);
        assert!(bus.is_empty());
        assert!(!bus.is_full());
    }

    #[test]
    fn publish_and_read_tracks_processing_ownership() {
        let bus = PacketBus::new(16);
        let original = observation(123);
        let id = original.observation_id;
        bus.publish(original).unwrap();
        let received = bus.read().unwrap();
        assert_eq!(received.observation_id, id);
        assert_eq!(received.packet.as_slice(), &[1, 2, 3, 4]);
        bus.release_processing(id).unwrap();
    }

    #[test]
    fn host_transfer_and_release_are_terminal() {
        let bus = PacketBus::new(16);
        let id = ObservationId::new(1);
        bus.publish(observation(1)).unwrap();
        bus.read().unwrap();
        bus.transfer_to_host(id).unwrap();
        bus.release_host(id).unwrap();
        assert!(bus.release_host(id).is_err());
    }

    #[test]
    fn processing_can_be_requeued_without_new_record() {
        let bus = PacketBus::new(16);
        let item = observation(7);
        let id = item.observation_id;
        bus.publish(item).unwrap();
        let item = bus.read().unwrap();
        bus.requeue_processing(item).unwrap();
        let item = bus.read().unwrap();
        assert_eq!(item.observation_id, id);
        bus.release_processing(id).unwrap();
    }

    #[test]
    fn full_bus_does_not_create_orphan_ownership() {
        let bus = PacketBus::new(1);
        bus.publish(observation(1)).unwrap();
        assert!(bus.publish(observation(2)).is_err());
        let item = bus.read().unwrap();
        bus.release_processing(item.observation_id).unwrap();
    }
}
