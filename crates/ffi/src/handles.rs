// network-engine\crates\ffi\src\handles.rs

use std::sync::atomic::{AtomicU64, Ordering};

static HANDLE_COUNTER: AtomicU64 = AtomicU64::new(1);

pub fn next_handle() -> u64 {
    loop {
        let handle = HANDLE_COUNTER.fetch_add(1, Ordering::Relaxed);

        if handle != 0 {
            return handle;
        }
    }
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Handle(pub u64);

impl Handle {
    pub fn new() -> Self {
        Self(next_handle())
    }

    pub const fn null() -> Self {
        Self(0)
    }

    pub const fn is_valid(self) -> bool {
        self.0 != 0
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

impl Default for Handle {
    fn default() -> Self {
        Self::null()
    }
}