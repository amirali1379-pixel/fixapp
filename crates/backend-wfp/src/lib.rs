// NOTE: no crate-wide `forbid(unsafe_code)` here — `engine.rs` and
// `management.rs` need `unsafe` for native WFP FFI calls.
// filter.rs, flow.rs and metadata.rs keep their own local
// `#![forbid(unsafe_code)]` since they never need to leave safe Rust.

mod engine;
mod filter;
mod flow;
mod layer_keys;
mod management;
mod metadata;

pub use engine::{WfpEngine, WfpEngineState};
pub use filter::{WfpAction, WfpFilter, WfpFilterCondition};
pub use flow::{WfpFlow, WfpFlowState};
pub use management::{add_sublayer, remove_sublayer};
pub use metadata::WfpMetadata;

pub const WFP_BACKEND_NAME: &str = "wfp";
pub const WFP_BACKEND_VERSION: &str = "0.1.0";
