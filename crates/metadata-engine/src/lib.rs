// crates/metadata-engine/src/lib.rs

// DNS enrichment is currently disabled.
//
// Per the updated architecture (see CORE_MODEL.txt and PROJECT_NATURE.txt),
// metadata must be fed only from:
//   - packet payloads (captured from the interface)
//   - backend observations
//   - host-provided metadata
//
// The previous `dns.rs` implementation used Windows DNS client APIs
// (GetNameInfoW / getnameinfo) which violates the Data Source Rule:
//   The CORE must not read from the Windows host machine
//   beyond its own interface.
//
// When DNS enrichment is needed again, it must be implemented as a
// packet-payload DNS response extractor (i.e. a DNS packet parser),
// not as a Windows DNS client wrapper.

pub mod cache;
pub mod provenance;
pub mod workers;

pub use cache::*;
pub use provenance::*;
pub use workers::*;