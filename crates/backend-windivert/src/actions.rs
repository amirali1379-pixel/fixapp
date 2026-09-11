//! Packet actions for an open WinDivert handle.
//!
//! Observation and action are kept separate, per the architecture:
//! receiving a packet (`recv_packet`) never implies an action was
//! taken on it. The caller decides PASS / DROP / MODIFY+REINJECT
//! afterwards, based on Host-controlled policy — this module never
//! drops a packet on its own initiative.

use crate::ffi::{self, WinDivertAddress};
use crate::handle::{WinDivertError, WinDivertHandle};

pub const MAX_PACKET_SIZE: usize = 65_535;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterceptedPacket {
    pub data: Vec<u8>,
    pub direction: PacketDirection,
    pub interface_index: u32,
    pub loopback: bool,
    pub impostor: bool,
    address: WinDivertAddress,
}

impl InterceptedPacket {
    fn from_native(data: Vec<u8>, address: WinDivertAddress) -> Self {
        Self {
            data,
            direction: if address.is_outbound() {
                PacketDirection::Outbound
            } else {
                PacketDirection::Inbound
            },
            interface_index: address.interface_index(),
            loopback: address.is_loopback(),
            impostor: address.is_impostor(),
            address,
        }
    }

    /// Returns the native address metadata required for a later action.
    /// The address is copied; ownership remains with the intercepted packet.
    pub fn address(&self) -> WinDivertAddress {
        self.address
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketDirection {
    Inbound,
    Outbound,
}

pub fn recv_packet(handle: &WinDivertHandle) -> Result<InterceptedPacket, WinDivertError> {
    let native = handle.require_open()?;
    let mut buffer = vec![0u8; MAX_PACKET_SIZE];
    let mut recv_len: u32 = 0;
    let mut addr = WinDivertAddress::zeroed();

    let ok = unsafe {
        ffi::WinDivertRecv(
            native,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            &mut recv_len,
            &mut addr,
        )
    };

    if ok == 0 {
        return Err(WinDivertError::RecvFailed);
    }

    let received = recv_len as usize;
    if received == 0 {
        return Err(WinDivertError::InvalidPacket);
    }
    if received > buffer.len() {
        return Err(WinDivertError::PacketTooLarge);
    }

    buffer.truncate(received);
    Ok(InterceptedPacket::from_native(buffer, addr))
}

pub fn pass(handle: &WinDivertHandle, packet: &InterceptedPacket) -> Result<(), WinDivertError> {
    reinject(handle, &packet.data, &packet.address)
}

pub fn drop_packet(_packet: InterceptedPacket) {}

pub fn reinject(
    handle: &WinDivertHandle,
    data: &[u8],
    address: &WinDivertAddress,
) -> Result<(), WinDivertError> {
    let native = handle.require_open()?;
    if data.is_empty() {
        return Err(WinDivertError::InvalidOperation);
    }
    if data.len() > MAX_PACKET_SIZE {
        return Err(WinDivertError::PacketTooLarge);
    }

    let mut packet = data.to_vec();
    let mut addr = *address;

    let checksum_ok = unsafe {
        ffi::WinDivertHelperCalcChecksums(
            packet.as_mut_ptr(),
            packet.len() as u32,
            &mut addr,
            0,
        )
    };
    if checksum_ok == 0 {
        return Err(WinDivertError::InvalidPacket);
    }

    let mut send_len: u32 = 0;
    let ok = unsafe {
        ffi::WinDivertSend(
            native,
            packet.as_ptr(),
            packet.len() as u32,
            &mut send_len,
            &addr,
        )
    };

    if ok == 0 {
        return Err(WinDivertError::SendFailed);
    }
    if send_len as usize != packet.len() {
        return Err(WinDivertError::SendFailed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handle::{WinDivertConfig, WinDivertLayer};

    fn closed_handle() -> WinDivertHandle {
        WinDivertHandle::new(
            WinDivertConfig::new("true", WinDivertLayer::Network).unwrap(),
        )
    }

    #[test]
    fn recv_requires_open_handle() {
        let handle = closed_handle();
        assert_eq!(recv_packet(&handle), Err(WinDivertError::InvalidOperation));
    }

    #[test]
    fn reinject_rejects_empty_payload() {
        let handle = closed_handle();
        let addr = WinDivertAddress::zeroed();
        assert_eq!(reinject(&handle, &[], &addr), Err(WinDivertError::InvalidOperation));
    }

    #[test]
    fn reinject_requires_open_handle_for_nonempty_payload() {
        let handle = closed_handle();
        let addr = WinDivertAddress::zeroed();
        assert_eq!(reinject(&handle, &[1, 2, 3], &addr), Err(WinDivertError::InvalidOperation));
    }

    #[test]
    fn drop_packet_accepts_ownership_without_panicking() {
        let addr = WinDivertAddress::zeroed();
        let packet = InterceptedPacket::from_native(vec![1, 2, 3], addr);
        drop_packet(packet);
    }

    #[test]
    fn packet_direction_reflects_address_flags() {
        let mut addr = WinDivertAddress::zeroed();
        addr.flags_raw = 1 << 17;
        let packet = InterceptedPacket::from_native(vec![9], addr);
        assert_eq!(packet.direction, PacketDirection::Outbound);
    }
}
