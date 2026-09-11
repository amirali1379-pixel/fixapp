use crate::handle::WinDivertError;
use crate::packet::WinDivertPacket;
use std::collections::VecDeque;

const DEFAULT_MAX_PACKETS: usize = 4096;
const DEFAULT_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Bounded backend-local queue. Full conditions remain observable to the Engine.
pub struct WinDivertQueue {
    packets: VecDeque<WinDivertPacket>,
    max_packets: usize,
    max_bytes: usize,
    current_bytes: usize,
}

impl WinDivertQueue {
    pub fn new() -> Self { Self::with_limits(DEFAULT_MAX_PACKETS, DEFAULT_MAX_BYTES) }
    pub fn with_limits(max_packets: usize, max_bytes: usize) -> Self {
        let max_packets = max_packets.max(1);
        let max_bytes = max_bytes.max(1);
        Self { packets: VecDeque::with_capacity(max_packets.min(DEFAULT_MAX_PACKETS)), max_packets, max_bytes, current_bytes: 0 }
    }
    pub fn push(&mut self, packet: WinDivertPacket) -> Result<(), WinDivertError> {
        let size = packet.len();
        if size == 0 { return Err(WinDivertError::InvalidPacket); }
        if size > self.max_bytes { return Err(WinDivertError::PacketTooLarge); }
        if self.packets.len() >= self.max_packets { return Err(WinDivertError::QueueFull); }
        let total = self.current_bytes.checked_add(size).ok_or(WinDivertError::QueueFull)?;
        if total > self.max_bytes { return Err(WinDivertError::QueueFull); }
        self.current_bytes = total;
        self.packets.push_back(packet);
        Ok(())
    }
    pub fn pop(&mut self) -> Result<WinDivertPacket, WinDivertError> {
        let packet = self.packets.pop_front().ok_or(WinDivertError::QueueEmpty)?;
        self.current_bytes = self.current_bytes.saturating_sub(packet.len());
        Ok(packet)
    }
    pub fn try_pop(&mut self) -> Option<WinDivertPacket> { self.pop().ok() }
    pub fn len(&self) -> usize { self.packets.len() }
    pub fn is_empty(&self) -> bool { self.packets.is_empty() }
    pub fn is_full(&self) -> bool { self.packets.len() >= self.max_packets || self.current_bytes >= self.max_bytes }
    pub fn current_bytes(&self) -> usize { self.current_bytes }
    pub fn max_packets(&self) -> usize { self.max_packets }
    pub fn max_bytes(&self) -> usize { self.max_bytes }
    pub fn clear(&mut self) { self.packets.clear(); self.current_bytes = 0; }
}

impl Default for WinDivertQueue { fn default() -> Self { Self::new() } }
