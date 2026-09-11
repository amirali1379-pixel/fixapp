#![forbid(unsafe_code)]

pub mod backpressure;
pub mod buffer;
pub mod bus;
pub mod ownership;
pub mod pool;
pub mod queue;

pub use backpressure::{
    BackpressureAction,
    BackpressureConfig,
    BackpressureController,
    BackpressureLevel,
};

pub use buffer::{
    BufferError,
    PacketBuffer,
};

pub use bus::PacketBus;

pub use ownership::{
    OwnedPacket,
    Owner,
    OwnershipTracker,
};

pub use pool::{
    BufferPool,
    PoolError,
};

pub use queue::{
    ObservationQueue,
    QueueError,
};

/// Re-export the authoritative packet observation contract.
///
/// PacketBus transports observations but does not redefine the
/// observation model. The authoritative definition remains in
/// network-core.
pub use network_core::{
    BackendSource,
    Direction,
    ObservationId,
    PacketObservation,
};