#![forbid(unsafe_code)]

//! Backend-manager state compatibility boundary.
//!
//! The authoritative backend lifecycle model lives in `backend.rs`.
//! This module preserves the historical `state` path without creating a
//! second lifecycle implementation.

pub use crate::backend::{BackendLifecycle, BackendRuntimeState};
