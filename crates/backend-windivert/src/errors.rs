#![forbid(unsafe_code)]

//! Compatibility error boundary for the historical `errors` module.
//! The canonical WinDivert error type is owned by `handle.rs`.

pub use crate::handle::WinDivertError;
