// crates/backend-contracts/src/lib.rs

#![forbid(unsafe_code)]

//! Backend capability contracts for the unified Network Engine.
//!
//! This crate is the single source of truth for the Engine's **intended**
//! capability layout of known native backends.
//!
//! It does NOT:
//! - start or stop backends
//! - prove capability availability at runtime
//! - override Host policy
//! - own backend lifecycle or health
//!
//! Backends themselves remain responsible for their native state.
//! The Engine uses these contracts only for capability planning and
//! backend complementarity.
//!
//! ## Usage
//!
//! The Engine registers well-known backend descriptors at startup:
//!
//! ```ignore
//! for descriptor in backend_contracts::all_known_descriptors() {
//!     engine.backend_manager.register(descriptor)?;
//! }
//! ```

mod kind;
mod known;

pub use kind::BackendKind;

pub use known::{
    all_known_descriptors,
    descriptor_for,
    etw_descriptor,
    iphelper_descriptor,
    npcap_descriptor,
    wfp_descriptor,
    windivert_descriptor,
};