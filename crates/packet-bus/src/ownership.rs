use std::sync::atomic::{AtomicU8, Ordering};

use network_core::{
    error::EngineError,
    ownership::OwnershipState,
};

/// Packet-bus view of the authoritative ownership lifecycle.
///
/// The numeric representation is kept stable for the packet-bus API while
/// the states mirror `network_core::OwnershipState` exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Owner {
    Allocated = 0,
    Backend = 1,
    Engine = 2,
    Bus = 3,
    Processing = 4,
    Host = 5,
    Released = 6,
}

impl Owner {
    fn as_core(self) -> OwnershipState {
        match self {
            Self::Allocated => OwnershipState::Allocated,
            Self::Backend => OwnershipState::BackendOwned,
            Self::Engine => OwnershipState::EngineOwned,
            Self::Bus => OwnershipState::BusOwned,
            Self::Processing => OwnershipState::ProcessingOwned,
            Self::Host => OwnershipState::HostOwned,
            Self::Released => OwnershipState::Released,
        }
    }

    /// Converts the authoritative `network_core::OwnershipState`
    /// into the packet-bus `Owner` view.
    ///
    /// `as_core()` and `from_core()` are inverse conversions
    /// and must remain in sync.

    pub(crate) fn from_core(state: OwnershipState) -> Self {
        match state {
            OwnershipState::Allocated => Self::Allocated,
            OwnershipState::BackendOwned => Self::Backend,
            OwnershipState::EngineOwned => Self::Engine,
            OwnershipState::BusOwned => Self::Bus,
            OwnershipState::ProcessingOwned => Self::Processing,
            OwnershipState::HostOwned => Self::Host,
            OwnershipState::Released => Self::Released,
        }
    }

    pub fn is_released(self) -> bool {
        matches!(self, Self::Released)
    }

    pub fn can_transfer_to(self, target: Owner) -> bool {
        network_core::ownership::transition_ownership(
            self.as_core(),
            target.as_core(),
        )
        .is_ok()
    }
}

#[derive(Debug)]
pub struct OwnershipTracker {
    owner: AtomicU8,
}

impl OwnershipTracker {
    pub fn new(owner: Owner) -> Self {
        Self {
            owner: AtomicU8::new(owner as u8),
        }
    }

    pub fn owner(&self) -> Owner {
        match self.owner.load(Ordering::Acquire) {
            0 => Owner::Allocated,
            1 => Owner::Backend,
            2 => Owner::Engine,
            3 => Owner::Bus,
            4 => Owner::Processing,
            5 => Owner::Host,
            _ => Owner::Released,
        }
    }

    pub fn transfer(
        &self,
        expected: Owner,
        target: Owner,
    ) -> Result<(), EngineError> {
        network_core::ownership::transition_ownership(
            expected.as_core(),
            target.as_core(),
        )
        .map(|_| ())?;

        self.owner
            .compare_exchange(
                expected as u8,
                target as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|_| EngineError::invalid_state_transition())
    }

    pub fn allocated_to_backend(&self) -> Result<(), EngineError> {
        self.transfer(Owner::Allocated, Owner::Backend)
    }

    pub fn backend_to_engine(&self) -> Result<(), EngineError> {
        self.transfer(Owner::Backend, Owner::Engine)
    }

    pub fn engine_to_bus(&self) -> Result<(), EngineError> {
        self.transfer(Owner::Engine, Owner::Bus)
    }

    pub fn bus_to_processing(&self) -> Result<(), EngineError> {
        self.transfer(Owner::Bus, Owner::Processing)
    }

    pub fn processing_to_engine(&self) -> Result<(), EngineError> {
        self.transfer(Owner::Processing, Owner::Engine)
    }

    pub fn processing_to_host(&self) -> Result<(), EngineError> {
        self.transfer(Owner::Processing, Owner::Host)
    }

    pub fn engine_to_host(&self) -> Result<(), EngineError> {
        self.transfer(Owner::Engine, Owner::Host)
    }

    pub fn engine_release(&self) -> Result<(), EngineError> {
        self.transfer(Owner::Engine, Owner::Released)
    }

    pub fn host_release(&self) -> Result<(), EngineError> {
        self.transfer(Owner::Host, Owner::Released)
    }

    pub fn release(&self) -> Result<(), EngineError> {
        let current = self.owner();

        if current == Owner::Released {
            return Err(EngineError::invalid_handle());
        }

        self.transfer(current, Owner::Released)
    }

    pub fn is_owned_by(&self, owner: Owner) -> bool {
        self.owner() == owner
    }
}

impl Default for OwnershipTracker {
    fn default() -> Self {
        Self::new(Owner::Allocated)
    }
}

#[derive(Debug)]
pub struct OwnedPacket {
    tracker: OwnershipTracker,
    data: Vec<u8>,
}

impl OwnedPacket {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            tracker: OwnershipTracker::default(),
            data,
        }
    }

    pub fn owner(&self) -> Owner {
        self.tracker.owner()
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn allocated_to_backend(&self) -> Result<(), EngineError> {
        self.tracker.allocated_to_backend()
    }

    pub fn backend_to_engine(&self) -> Result<(), EngineError> {
        self.tracker.backend_to_engine()
    }

    pub fn engine_to_bus(&self) -> Result<(), EngineError> {
        self.tracker.engine_to_bus()
    }

    pub fn bus_to_processing(&self) -> Result<(), EngineError> {
        self.tracker.bus_to_processing()
    }

    pub fn processing_to_engine(&self) -> Result<(), EngineError> {
        self.tracker.processing_to_engine()
    }

    pub fn processing_to_host(&self) -> Result<(), EngineError> {
        self.tracker.processing_to_host()
    }

    pub fn engine_to_host(&self) -> Result<(), EngineError> {
        self.tracker.engine_to_host()
    }

    pub fn engine_release(&mut self) -> Result<(), EngineError> {
        self.tracker.engine_release()?;
        self.data.clear();
        Ok(())
    }

    pub fn host_release(&mut self) -> Result<(), EngineError> {
        self.tracker.host_release()?;
        self.data.clear();
        Ok(())
    }

    pub fn release(&mut self) -> Result<(), EngineError> {
        self.tracker.release()?;
        self.data.clear();
        Ok(())
    }

    pub fn into_data(self) -> Result<Vec<u8>, EngineError> {
        if self.owner() == Owner::Released {
            return Err(EngineError::invalid_handle());
        }

        Ok(self.data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_owner_is_allocated() {
        let tracker = OwnershipTracker::default();

        assert_eq!(tracker.owner(), Owner::Allocated);
        assert!(!tracker.owner().is_released());
    }

    #[test]
    fn allocation_can_transfer_to_backend() {
        let tracker = OwnershipTracker::default();

        tracker.allocated_to_backend().unwrap();

        assert_eq!(tracker.owner(), Owner::Backend);
    }

    #[test]
    fn complete_lifecycle_is_valid() {
        let tracker = OwnershipTracker::default();

        tracker.allocated_to_backend().unwrap();
        tracker.backend_to_engine().unwrap();
        tracker.engine_to_bus().unwrap();
        tracker.bus_to_processing().unwrap();
        tracker.processing_to_host().unwrap();
        tracker.host_release().unwrap();

        assert_eq!(tracker.owner(), Owner::Released);
    }

    #[test]
    fn processing_can_return_to_engine() {
        let tracker = OwnershipTracker::new(Owner::Processing);

        tracker.processing_to_engine().unwrap();

        assert_eq!(tracker.owner(), Owner::Engine);
    }

    #[test]
    fn processing_can_transfer_to_host() {
        let tracker = OwnershipTracker::new(Owner::Processing);

        tracker.processing_to_host().unwrap();

        assert_eq!(tracker.owner(), Owner::Host);
    }

    #[test]
    fn invalid_direct_transfer_is_rejected() {
        let tracker = OwnershipTracker::new(Owner::Allocated);

        assert!(
            tracker
                .transfer(Owner::Allocated, Owner::Host)
                .is_err()
        );

        assert_eq!(tracker.owner(), Owner::Allocated);
    }

    #[test]
    fn released_cannot_be_transferred() {
        let tracker = OwnershipTracker::new(Owner::Released);

        assert!(tracker.backend_to_engine().is_err());
        assert!(tracker.engine_to_host().is_err());
        assert!(tracker.release().is_err());

        assert_eq!(tracker.owner(), Owner::Released);
    }

    #[test]
    fn compare_exchange_prevents_double_transfer() {
        let tracker = OwnershipTracker::new(Owner::Backend);

        tracker.backend_to_engine().unwrap();

        assert!(tracker.backend_to_engine().is_err());
        assert_eq!(tracker.owner(), Owner::Engine);
    }

    #[test]
    fn owned_packet_starts_allocated() {
        let packet = OwnedPacket::new(vec![1, 2, 3, 4]);

        assert_eq!(packet.owner(), Owner::Allocated);
        assert_eq!(packet.len(), 4);
        assert_eq!(packet.as_slice(), &[1, 2, 3, 4]);
    }

    #[test]
    fn owned_packet_follows_lifecycle() {
        let mut packet = OwnedPacket::new(vec![1, 2, 3]);

        packet.allocated_to_backend().unwrap();
        packet.backend_to_engine().unwrap();
        packet.engine_to_bus().unwrap();
        packet.bus_to_processing().unwrap();
        packet.processing_to_host().unwrap();
        packet.host_release().unwrap();

        assert_eq!(packet.owner(), Owner::Released);
        assert!(packet.is_empty());
    }

    #[test]
    fn emergency_release_works_from_active_states() {
        for owner in [
            Owner::Allocated,
            Owner::Backend,
            Owner::Engine,
            Owner::Bus,
            Owner::Processing,
            Owner::Host,
        ] {
            let tracker = OwnershipTracker::new(owner);
            tracker.release().unwrap();
            assert_eq!(tracker.owner(), Owner::Released);
        }
    }

    #[test]
    fn owner_mapping_matches_core_states() {
        for owner in [
            Owner::Allocated,
            Owner::Backend,
            Owner::Engine,
            Owner::Bus,
            Owner::Processing,
            Owner::Host,
            Owner::Released,
        ] {
            assert_eq!(Owner::from_core(owner.as_core()), owner);
        }
    }
}