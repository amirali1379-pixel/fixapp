//! WinDivert native handle lifecycle and configuration.

use crate::ffi;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WinDivertLayer { Network, NetworkForward, Flow, Socket, Reflect }

impl WinDivertLayer {
    fn as_raw(self) -> u8 {
        match self {
            Self::Network => ffi::WINDIVERT_LAYER_NETWORK,
            Self::NetworkForward => ffi::WINDIVERT_LAYER_NETWORK_FORWARD,
            Self::Flow => ffi::WINDIVERT_LAYER_FLOW,
            Self::Socket => ffi::WINDIVERT_LAYER_SOCKET,
            Self::Reflect => ffi::WINDIVERT_LAYER_REFLECT,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinDivertConfig {
    pub filter: String,
    pub layer: WinDivertLayer,
    pub priority: i16,
    pub sniff_only: bool,
    /// Opens a handle that can send/reinject without becoming another
    /// receiver of the traffic selected by the filter.
    pub send_only: bool,
}

impl WinDivertConfig {
    pub fn new(filter: impl Into<String>, layer: WinDivertLayer) -> Result<Self, WinDivertError> {
        let filter = filter.into();
        ffi::validate_filter(&filter).map_err(|_| WinDivertError::FilterFailed)?;
        Ok(Self {
            filter,
            layer,
            priority: 0,
            sniff_only: false,
            send_only: false,
        })
    }

    fn raw_flags(&self) -> u64 {
        let mut flags = 0;
        if self.sniff_only {
            flags |= ffi::WINDIVERT_FLAG_SNIFF;
        }
        if self.send_only {
            flags |= ffi::WINDIVERT_FLAG_SEND_ONLY;
        }
        flags
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WinDivertHandleState { Closed, Opening, Open, Closing, Failed }

impl WinDivertHandleState {
    pub fn can_open(self) -> bool { matches!(self, Self::Closed | Self::Failed) }
    pub fn can_close(self) -> bool { matches!(self, Self::Open | Self::Failed) }
}

/// Unified WinDivert error boundary used by handle, capture, packet and queue code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WinDivertError {
    InitFailed,
    OpenFailed,
    FilterFailed,
    RecvFailed,
    SendFailed,
    CloseFailed,
    InvalidOperation,
    QueueError,
    InvalidPacket,
    PacketTooLarge,
    QueueFull,
    QueueEmpty,
}

#[derive(Debug)]
pub struct WinDivertHandle {
    config: WinDivertConfig,
    state: WinDivertHandleState,
    native: Option<*mut core::ffi::c_void>,
}

// SAFETY: the handle is accessed through exclusive &mut self methods.
unsafe impl Send for WinDivertHandle {}

impl WinDivertHandle {
    pub fn new(config: WinDivertConfig) -> Self {
        Self { config, state: WinDivertHandleState::Closed, native: None }
    }

    pub fn state(&self) -> WinDivertHandleState { self.state }
    pub fn is_open(&self) -> bool { self.state == WinDivertHandleState::Open }
    pub fn config(&self) -> &WinDivertConfig { &self.config }

    pub fn open(&mut self) -> Result<(), WinDivertError> {
        if !self.state.can_open() { return Err(WinDivertError::InvalidOperation); }
        self.state = WinDivertHandleState::Opening;
        let filter = std::ffi::CString::new(self.config.filter.as_str())
            .map_err(|_| WinDivertError::FilterFailed)?;
        let handle = unsafe {
            ffi::WinDivertOpen(filter.as_ptr(), self.config.layer.as_raw(), self.config.priority, self.config.raw_flags())
        };
        if handle.is_null() || handle as isize == -1 {
            self.state = WinDivertHandleState::Failed;
            return Err(WinDivertError::OpenFailed);
        }
        self.native = Some(handle);
        self.state = WinDivertHandleState::Open;
        Ok(())
    }

    pub fn close(&mut self) -> Result<(), WinDivertError> {
        if self.state == WinDivertHandleState::Closed { return Ok(()); }
        if !self.state.can_close() { return Err(WinDivertError::InvalidOperation); }
        self.state = WinDivertHandleState::Closing;
        if let Some(handle) = self.native.take() {
            if unsafe { ffi::WinDivertClose(handle) } == 0 {
                self.state = WinDivertHandleState::Failed;
                return Err(WinDivertError::CloseFailed);
            }
        }
        self.state = WinDivertHandleState::Closed;
        Ok(())
    }

    pub fn require_open(&self) -> Result<*mut core::ffi::c_void, WinDivertError> {
        if !self.is_open() { return Err(WinDivertError::InvalidOperation); }
        self.native.ok_or(WinDivertError::InvalidOperation)
    }

    pub fn set_queue_length(&mut self, packets: u64) -> Result<(), WinDivertError> {
        let handle = self.require_open()?;
        let status = unsafe { ffi::WinDivertSetParam(handle, ffi::WINDIVERT_PARAM_QUEUE_LENGTH, packets) };
        if status == 0 { return Err(WinDivertError::QueueError); }
        Ok(())
    }
}

impl Drop for WinDivertHandle {
    fn drop(&mut self) {
        if let Some(handle) = self.native.take() { unsafe { ffi::WinDivertClose(handle); } }
        self.state = WinDivertHandleState::Closed;
    }
}
