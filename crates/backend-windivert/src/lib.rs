pub mod actions;
pub mod capture;
pub mod errors;
pub mod ffi;
pub mod filter;
pub mod handle;
pub mod packet;
pub mod queue;

pub use actions::{drop_packet, pass, recv_packet, reinject, InterceptedPacket, PacketDirection, MAX_PACKET_SIZE};
pub use capture::CaptureConfig;
pub use errors::WinDivertError;
pub use filter::WinDivertFilter;
pub use handle::{WinDivertConfig, WinDivertHandle, WinDivertHandleState, WinDivertLayer};
pub use packet::{PacketDirection as QueuePacketDirection, WinDivertPacket};
pub use queue::WinDivertQueue;

pub const WINDIVERT_BACKEND_NAME: &str = "windivert";
pub const WINDIVERT_BACKEND_VERSION: &str = "0.1.0";

#[derive(Debug)]
pub struct WinDivertBackend {
    handle: WinDivertHandle,
}

impl WinDivertBackend {
    pub fn new(config: WinDivertConfig) -> Self {
        Self { handle: WinDivertHandle::new(config) }
    }

    pub fn from_capture_config(config: CaptureConfig) -> Result<Self, WinDivertError> {
        Ok(Self::new(config.into_handle_config()?))
    }

    pub fn start(&mut self) -> Result<(), WinDivertError> { self.handle.open() }
    pub fn stop(&mut self) -> Result<(), WinDivertError> { self.handle.close() }
    pub fn is_running(&self) -> bool { self.handle.is_open() }
    pub fn state(&self) -> WinDivertHandleState { self.handle.state() }
    pub fn recv(&self) -> Result<InterceptedPacket, WinDivertError> { recv_packet(&self.handle) }
    pub fn pass(&self, packet: &InterceptedPacket) -> Result<(), WinDivertError> { pass(&self.handle, packet) }
    pub fn drop(&self, packet: InterceptedPacket) { drop_packet(packet) }

    /// Sends an already captured packet using the native address preserved by
    /// the observation layer. This is the action-side primitive used when the
    /// Engine retained an opaque WinDivert address context.
    pub fn reinject_with_context(
        &self,
        data: &[u8],
        context: &[u8],
    ) -> Result<(), WinDivertError> {
        let address = ffi::WinDivertAddress::from_bytes(context)
            .ok_or(WinDivertError::InvalidOperation)?;
        reinject(&self.handle, data, &address)
    }

    pub fn reinject(&self, data: &[u8], address: &ffi::WinDivertAddress) -> Result<(), WinDivertError> { reinject(&self.handle, data, address) }
    pub fn set_queue_length(&mut self, packets: u64) -> Result<(), WinDivertError> { self.handle.set_queue_length(packets) }
}

impl Drop for WinDivertBackend {
    fn drop(&mut self) { let _ = self.handle.close(); }
}
