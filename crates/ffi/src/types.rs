// crates/ffi/src/types.rs

use std::os::raw::{c_char, c_int, c_uint, c_ulonglong, c_void};

/// Opaque packet handle exposed through the C ABI.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NePacketHandle {
    pub id: c_ulonglong,
}

impl NePacketHandle {
    pub const NULL: Self = Self { id: 0 };

    pub const fn new(id: c_ulonglong) -> Self {
        Self { id }
    }

    pub const fn is_valid(self) -> bool {
        self.id != 0
    }
}

impl Default for NePacketHandle {
    fn default() -> Self {
        Self::NULL
    }
}

/// Packet returned by the Host-facing packet_read ABI.
///
/// The handle remains valid until packet_release or a terminal packet
/// action consumes it. `data` points to engine-owned packet storage and is
/// valid while the associated handle remains valid.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NePacketDescriptor {
    pub packet_handle: c_ulonglong,
    pub data: *const c_void,
    pub len: c_uint,
    pub backend_source: c_int,
    pub direction: c_int,
}

impl Default for NePacketDescriptor {
    fn default() -> Self {
        Self {
            packet_handle: 0,
            data: std::ptr::null(),
            len: 0,
            backend_source: 0,
            direction: 0,
        }
    }
}

/// Backend information exposed through the C ABI.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NeBackendInfo {
    pub name: [c_char; 64],
    pub status: c_int,
    pub capability_count: c_uint,
}

impl Default for NeBackendInfo {
    fn default() -> Self {
        Self {
            name: [0; 64],
            status: 0,
            capability_count: 0,
        }
    }
}

/// Packet action requested by the host.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NePacketAction {
    pub action: c_int,
}

impl NePacketAction {
    pub const PASS: c_int = 0;
    pub const DROP: c_int = 1;
    pub const MODIFY: c_int = 2;
    pub const REINJECT: c_int = 3;

    pub const fn new(action: c_int) -> Self {
        Self { action }
    }

    pub const fn is_valid(self) -> bool {
        matches!(
            self.action,
            Self::PASS
                | Self::DROP
                | Self::MODIFY
                | Self::REINJECT
        )
    }
}

impl Default for NePacketAction {
    fn default() -> Self {
        Self::new(Self::PASS)
    }
}

/// Engine statistics exposed through the C ABI.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct NeStatistics {
    pub packets_received: c_ulonglong,
    pub bytes_received: c_ulonglong,
    pub packets_dropped: c_ulonglong,
    pub packets_forwarded: c_ulonglong,
    pub flows_active: c_ulonglong,
}

/// Engine initialization configuration.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NeInitConfig {
    pub queue_capacity: c_uint,
    pub pool_max_size: c_uint,
    pub buffer_capacity: c_uint,
    pub max_flows: c_uint,
}

impl Default for NeInitConfig {
    fn default() -> Self {
        Self {
            queue_capacity: 4096,
            pool_max_size: 1024,
            buffer_capacity: 65536,
            max_flows: 65536,
        }
    }
}

impl NeInitConfig {
    pub const fn is_valid(self) -> bool {
        self.queue_capacity > 0
            && self.pool_max_size > 0
            && self.buffer_capacity > 0
            && self.max_flows > 0
    }
}

/// Host-owned Gateway/NAT/Routing/Forwarding configuration.
///
/// This structure carries the Host's intent through the stable C ABI.
/// The Engine validates and normalizes this configuration into runtime
/// state; it never invents Gateway/NAT policy on its own.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NeGatewayConfig {
    pub enabled: c_uint,
    pub default_decision: c_uint,
    pub nat_enabled: c_uint,
    pub nat_mode: c_uint,
    pub external_interface_id: c_uint,
    pub forwarding_enabled: c_uint,
    pub ingress_interface_id: c_uint,
    pub egress_interface_id: c_uint,
    pub routing_table_id: c_uint,
    pub preferred_interface_id: c_uint,
}

impl Default for NeGatewayConfig {
    fn default() -> Self {
        Self {
            enabled: 0,
            default_decision: 0,
            nat_enabled: 0,
            nat_mode: 0,
            external_interface_id: 0,
            forwarding_enabled: 0,
            ingress_interface_id: 0,
            egress_interface_id: 0,
            routing_table_id: 0,
            preferred_interface_id: 0,
        }
    }
}