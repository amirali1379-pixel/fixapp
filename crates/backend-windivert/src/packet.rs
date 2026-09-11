use crate::handle::WinDivertError;

const MAX_PACKET_SIZE: usize = 65_535;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinDivertPacket {
    data: Vec<u8>,
    timestamp_ns: u64,
    direction: PacketDirection,
    interface_index: u32,
    sub_interface_index: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketDirection {
    Inbound,
    Outbound,
    Unknown,
}

impl WinDivertPacket {
    pub fn new(data: Vec<u8>) -> Result<Self, WinDivertError> {
        if data.is_empty() { return Err(WinDivertError::InvalidPacket); }
        if data.len() > MAX_PACKET_SIZE { return Err(WinDivertError::PacketTooLarge); }
        Ok(Self { data, timestamp_ns: 0, direction: PacketDirection::Unknown, interface_index: 0, sub_interface_index: 0 })
    }
    pub fn from_slice(data: &[u8]) -> Result<Self, WinDivertError> { Self::new(data.to_vec()) }
    pub fn data(&self) -> &[u8] { &self.data }
    pub fn data_mut(&mut self) -> &mut [u8] { &mut self.data }
    pub fn into_data(self) -> Vec<u8> { self.data }
    pub fn len(&self) -> usize { self.data.len() }
    pub fn is_empty(&self) -> bool { self.data.is_empty() }
    pub fn timestamp_ns(&self) -> u64 { self.timestamp_ns }
    pub fn set_timestamp_ns(&mut self, timestamp_ns: u64) { self.timestamp_ns = timestamp_ns; }
    pub fn direction(&self) -> PacketDirection { self.direction }
    pub fn set_direction(&mut self, direction: PacketDirection) { self.direction = direction; }
    pub fn interface_index(&self) -> u32 { self.interface_index }
    pub fn set_interface_index(&mut self, index: u32) { self.interface_index = index; }
    pub fn sub_interface_index(&self) -> u32 { self.sub_interface_index }
    pub fn set_sub_interface_index(&mut self, index: u32) { self.sub_interface_index = index; }
    pub fn replace_data(&mut self, data: Vec<u8>) -> Result<(), WinDivertError> {
        if data.is_empty() { return Err(WinDivertError::InvalidPacket); }
        if data.len() > MAX_PACKET_SIZE { return Err(WinDivertError::PacketTooLarge); }
        self.data = data;
        Ok(())
    }
}
