// crates/backend-iphelper/src/sockaddr.rs
//
// Project-local Windows sockaddr layout definitions.
//
// `libc` on Windows does not expose `sockaddr_in` / `sockaddr_in6`.
// These definitions match the Windows SDK layout exactly so that
// structures returned by Windows APIs can be interpreted safely.

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

/// Base Windows socket address header (sa_family + sa_data).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SOCKADDR {
    pub sa_family: u16,
    pub sa_data: [u8; 14],
}

/// IPv4 socket address (Windows SDK layout).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SOCKADDR_IN {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: IN_ADDR,
    pub sin_zero: [u8; 8],
}

/// IPv4 address in Windows SDK layout.
#[repr(C)]
#[derive(Clone, Copy)]
pub union IN_ADDR {
    pub S_addr: u32,
    pub S_un_b: IN_ADDR_0,
}

impl std::fmt::Debug for IN_ADDR {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unsafe { write!(f, "IN_ADDR({:#010x})", self.S_addr) }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IN_ADDR_0 {
    pub s_b1: u8,
    pub s_b2: u8,
    pub s_b3: u8,
    pub s_b4: u8,
}

/// IPv6 socket address (Windows SDK layout).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SOCKADDR_IN6 {
    pub sin6_family: u16,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: IN6_ADDR,
    pub sin6_scope_id: u32,
}

/// IPv6 address in Windows SDK layout.
#[repr(C)]
#[derive(Clone, Copy)]
pub union IN6_ADDR {
    pub Byte: [u8; 16],
    pub Word: [u16; 8],
}

impl std::fmt::Debug for IN6_ADDR {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unsafe { write!(f, "IN6_ADDR({:?})", self.Byte) }
    }
}

impl SOCKADDR_IN {
    /// Returns the IPv4 address in network byte order as a u32.
    pub fn addr_u32(&self) -> u32 {
        unsafe { self.sin_addr.S_addr }
    }
}

impl SOCKADDR_IN6 {
    /// Returns the raw 16-byte IPv6 address.
    pub fn addr_bytes(&self) -> [u8; 16] {
        unsafe { self.sin6_addr.Byte }
    }
}