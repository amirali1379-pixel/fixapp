#![forbid(unsafe_code)]

//! Compatibility boundary for the historical Flow Table module path.
//!
//! `flow_table.rs` is the single canonical implementation. This module does
//! not define a second table; it only preserves the planned `table` boundary
//! and re-exports the canonical implementation.

pub use crate::flow_table::{FlowTable, FlowTableStats};
