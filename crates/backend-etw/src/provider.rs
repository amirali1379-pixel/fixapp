// crates/backend-etw/src/provider.rs

use crate::events::{EtwEvent, EtwEventId, EtwEventKind, EtwSeverity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtwError {
    AlreadyRunning,
    NotRunning,
    InvalidProviderName,
    EventRejected,
    RegistrationFailed,
}

#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy)]
struct GuidC {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

// Stable ETW provider identity owned by network-engine.dll.
// This value must remain unchanged across releases unless the provider
// identity is intentionally migrated.
#[cfg(windows)]
const PROVIDER_GUID: GuidC = GuidC {
    data1: 0x102bbc9c,
    data2: 0xca7d,
    data3: 0x43e3,
    data4: [0xa2, 0xde, 0x0d, 0xf9, 0x67, 0x44, 0x80, 0x63],
};

#[cfg(windows)]
mod raw {
    use super::GuidC;
    use std::os::raw::c_void;

    pub type RegHandle = u64;

    #[link(name = "advapi32")]
    extern "system" {
        pub fn EventRegister(
            provider_id: *const GuidC,
            enable_callback: *const c_void,
            callback_context: *const c_void,
            reg_handle: *mut RegHandle,
        ) -> u32;

        pub fn EventUnregister(reg_handle: RegHandle) -> u32;

        pub fn EventWriteString(
            reg_handle: RegHandle,
            level: u8,
            keyword: u64,
            string: *const u16,
        ) -> u32;
    }
}

#[cfg(windows)]
fn severity_to_etw_level(severity: EtwSeverity) -> u8 {
    match severity {
        EtwSeverity::Critical => 1,
        EtwSeverity::Error => 2,
        EtwSeverity::Warning => 3,
        EtwSeverity::Info => 4,
        EtwSeverity::Debug | EtwSeverity::Trace => 5,
    }
}

#[cfg(windows)]
fn to_wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[derive(Debug, Clone)]
pub struct EtwProvider {
    name: String,
    running: bool,
    #[cfg(windows)]
    handle: Option<raw::RegHandle>,
}

impl EtwProvider {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            running: false,
            #[cfg(windows)]
            handle: None,
        }
    }

    pub fn start(&mut self) -> Result<(), EtwError> {
        if self.running {
            return Err(EtwError::AlreadyRunning);
        }

        if self.name.trim().is_empty() {
            return Err(EtwError::InvalidProviderName);
        }

        #[cfg(windows)]
        {
            let mut handle: raw::RegHandle = 0;

            let status = unsafe {
                raw::EventRegister(
                    &PROVIDER_GUID,
                    std::ptr::null(),
                    std::ptr::null(),
                    &mut handle,
                )
            };

            if status != 0 || handle == 0 {
                return Err(EtwError::RegistrationFailed);
            }

            self.handle = Some(handle);
        }

        self.running = true;
        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), EtwError> {
        if !self.running {
            return Err(EtwError::NotRunning);
        }

        #[cfg(windows)]
        {
            if let Some(handle) = self.handle.take() {
                unsafe {
                    raw::EventUnregister(handle);
                }
            }
        }

        self.running = false;
        Ok(())
    }

    pub fn is_running(&self) -> bool {
        self.running
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn event_id(&self, kind: EtwEventKind) -> EtwEventId {
        EtwEventId::for_kind(kind)
    }

    pub fn emit(&self, event: &EtwEvent) -> Result<(), EtwError> {
        if !self.running {
            return Err(EtwError::NotRunning);
        }

        if event.provider.trim().is_empty() || event.message.trim().is_empty() {
            return Err(EtwError::EventRejected);
        }

        #[cfg(windows)]
        {
            let handle = self.handle.ok_or(EtwError::NotRunning)?;
            let wide = to_wide_null(&event.to_string());

            let status = unsafe {
                raw::EventWriteString(
                    handle,
                    severity_to_etw_level(event.severity),
                    0,
                    wide.as_ptr(),
                )
            };

            if status != 0 {
                return Err(EtwError::EventRejected);
            }
        }

        Ok(())
    }

    pub fn emit_simple(
        &self,
        kind: EtwEventKind,
        severity: EtwSeverity,
        timestamp: u64,
        message: impl Into<String>,
    ) -> Result<(), EtwError> {
        let event = EtwEvent::new(
            EtwEventId::for_kind(kind),
            kind,
            severity,
            timestamp,
            &self.name,
            message,
        );

        self.emit(&event)
    }
}

impl Default for EtwProvider {
    fn default() -> Self {
        Self::new("network-engine")
    }
}

impl Drop for EtwProvider {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            if let Some(handle) = self.handle.take() {
                unsafe {
                    raw::EventUnregister(handle);
                }
            }
        }

        self.running = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_starts() {
        let mut provider = EtwProvider::new("network-engine");
        assert!(provider.start().is_ok());
        assert!(provider.is_running());
    }

    #[test]
    fn provider_stops() {
        let mut provider = EtwProvider::new("network-engine");
        provider.start().unwrap();
        assert!(provider.stop().is_ok());
        assert!(!provider.is_running());
    }

    #[test]
    fn starting_twice_returns_error() {
        let mut provider = EtwProvider::new("network-engine");
        provider.start().unwrap();
        assert_eq!(provider.start(), Err(EtwError::AlreadyRunning));
    }

    #[test]
    fn stopping_when_not_running_returns_error() {
        let mut provider = EtwProvider::new("network-engine");
        assert_eq!(provider.stop(), Err(EtwError::NotRunning));
    }

    #[test]
    fn empty_provider_name_is_rejected() {
        let mut provider = EtwProvider::new("   ");
        assert_eq!(provider.start(), Err(EtwError::InvalidProviderName));
    }

    #[test]
    fn event_requires_running_provider() {
        let provider = EtwProvider::new("network-engine");
        let result = provider.emit_simple(EtwEventKind::Diagnostic, EtwSeverity::Info, 1, "test");
        assert_eq!(result, Err(EtwError::NotRunning));
    }

    #[test]
    fn valid_event_is_accepted() {
        let mut provider = EtwProvider::new("network-engine");
        provider.start().unwrap();
        let result = provider.emit_simple(EtwEventKind::Diagnostic, EtwSeverity::Info, 1, "test");
        assert!(result.is_ok());
    }

    #[test]
    fn empty_event_message_is_rejected() {
        let mut provider = EtwProvider::new("network-engine");
        provider.start().unwrap();
        let event = EtwEvent::new(
            EtwEventId::DIAGNOSTIC,
            EtwEventKind::Diagnostic,
            EtwSeverity::Info,
            1,
            "network-engine",
            "   ",
        );
        assert_eq!(provider.emit(&event), Err(EtwError::EventRejected));
    }

    #[test]
    fn event_ids_are_available() {
        let provider = EtwProvider::default();
        assert_eq!(provider.event_id(EtwEventKind::PacketObserved), EtwEventId::PACKET_OBSERVED);
    }
}
