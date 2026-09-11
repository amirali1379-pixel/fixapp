use std::ffi::{CStr, OsString};

use crate::ffi::{
    pcap_findalldevs,
    pcap_freealldevs,
    PcapAddr,
    PcapIf,
    PCAP_IF_LOOPBACK,
    PCAP_IF_RUNNING,
    PCAP_IF_UP,
    PCAP_IF_WIRELESS,
    PCAP_NETMASK_UNKNOWN,
    PCAP_ERRBUF_SIZE,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceState {
    Unknown,
    Available,
    Open,
    Closed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpcapDevice {
    pub name: String,
    pub description: Option<String>,
    pub state: DeviceState,
    pub interface_index: Option<u32>,
}

impl NpcapDevice {
    pub fn new(name: impl Into<String>) -> Option<Self> {
        let name = name.into();

        if name.trim().is_empty() {
            return None;
        }

        Some(Self {
            name,
            description: None,
            state: DeviceState::Unknown,
            interface_index: None,
        })
    }

    pub fn set_description(
        &mut self,
        description: impl Into<String>,
    ) {
        let description = description.into();

        if description.trim().is_empty() {
            self.description = None;
        } else {
            self.description = Some(description);
        }
    }

    pub fn set_interface_index(
        &mut self,
        index: u32,
    ) {
        self.interface_index =
            if index == 0 {
                None
            } else {
                Some(index)
            };
    }

    pub fn is_available(&self) -> bool {
        self.state == DeviceState::Available
    }

    pub fn is_open(&self) -> bool {
        self.state == DeviceState::Open
    }

    pub fn mark_available(&mut self) {
        self.state = DeviceState::Available;
    }

    pub fn mark_open(&mut self) {
        self.state = DeviceState::Open;
    }

    pub fn mark_closed(&mut self) {
        self.state = DeviceState::Closed;
    }

    pub fn mark_failed(&mut self) {
        self.state = DeviceState::Failed;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceError {
    InvalidDeviceName,
    DeviceNotFound,
    DeviceAlreadyOpen,
    DeviceNotOpen,
    DeviceEnumerationFailed,
    DeviceOpenFailed,
}

#[derive(Debug, Default)]
pub struct DeviceManager {
    devices: Vec<NpcapDevice>,
}

impl DeviceManager {
    pub fn new() -> Self {
        Self {
            devices: Vec::new(),
        }
    }

    pub fn add(
        &mut self,
        device: NpcapDevice,
    ) -> Result<(), DeviceError> {
        if device.name.trim().is_empty() {
            return Err(DeviceError::InvalidDeviceName);
        }

        if self.devices.iter().any(|existing| {
            existing.name == device.name
        }) {
            return Ok(());
        }

        self.devices.push(device);

        Ok(())
    }

    pub fn get(
        &self,
        name: &str,
    ) -> Result<&NpcapDevice, DeviceError> {
        if name.trim().is_empty() {
            return Err(DeviceError::InvalidDeviceName);
        }

        self.devices
            .iter()
            .find(|device| device.name == name)
            .ok_or(DeviceError::DeviceNotFound)
    }

    pub fn get_mut(
        &mut self,
        name: &str,
    ) -> Result<&mut NpcapDevice, DeviceError> {
        if name.trim().is_empty() {
            return Err(DeviceError::InvalidDeviceName);
        }

        self.devices
            .iter_mut()
            .find(|device| device.name == name)
            .ok_or(DeviceError::DeviceNotFound)
    }

    pub fn open(
        &mut self,
        name: &str,
    ) -> Result<(), DeviceError> {
        let device = self.get_mut(name)?;

        if device.is_open() {
            return Err(DeviceError::DeviceAlreadyOpen);
        }

        if device.state == DeviceState::Failed {
            return Err(DeviceError::DeviceOpenFailed);
        }

        device.mark_open();

        Ok(())
    }

    pub fn close(
        &mut self,
        name: &str,
    ) -> Result<(), DeviceError> {
        let device = self.get_mut(name)?;

        if !device.is_open() {
            return Err(DeviceError::DeviceNotOpen);
        }

        device.mark_closed();

        Ok(())
    }

    pub fn remove(
        &mut self,
        name: &str,
    ) -> Result<NpcapDevice, DeviceError> {
        if name.trim().is_empty() {
            return Err(DeviceError::InvalidDeviceName);
        }

        let position = self
            .devices
            .iter()
            .position(|device| device.name == name)
            .ok_or(DeviceError::DeviceNotFound)?;

        Ok(self.devices.remove(position))
    }

    pub fn all(&self) -> &[NpcapDevice] {
        &self.devices
    }

    pub fn clear(&mut self) {
        self.devices.clear();
    }

    pub fn len(&self) -> usize {
        self.devices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// Enumerates the devices exposed by the native Npcap backend.
    ///
    /// The returned Npcap device name is the native name that must be passed
    /// back to `pcap_open_live`.
    #[cfg(windows)]
    pub fn enumerate() -> Result<Vec<NpcapDevice>, DeviceError> {
        unsafe {
            let mut alldevs: *mut PcapIf = std::ptr::null_mut();

            let mut errbuf = [0i8; PCAP_ERRBUF_SIZE];

            let result = pcap_findalldevs(
                &mut alldevs,
                errbuf.as_mut_ptr(),
            );

            if result != 0 {
                return Err(DeviceError::DeviceEnumerationFailed);
            }

            if alldevs.is_null() {
                return Err(DeviceError::DeviceEnumerationFailed);
            }

            let mut devices = Vec::new();
            let mut current = alldevs;
            let mut fallback_index = 1u32;

            while !current.is_null() {
                let device_ref = &*current;

                if let Some(name) =
                    c_string(device_ref.name)
                {
                    if let Some(mut device) =
                        NpcapDevice::new(name)
                    {
                        if let Some(description) =
                            c_string(device_ref.description)
                        {
                            device.set_description(description);
                        }

                        /*
                         * Npcap itself does not expose a reliable Windows
                         * interface index in PcapIf. Do not fabricate one
                         * from the Npcap list position.
                         *
                         * A real Windows interface-index mapping belongs
                         * to the IP Helper integration.
                         */
                        device.interface_index = None;

                        if device_ref.flags
                            & (PCAP_IF_UP | PCAP_IF_RUNNING)
                            != 0
                        {
                            device.mark_available();
                        } else {
                            device.state =
                                DeviceState::Closed;
                        }

                        /*
                         * Keep traversal deterministic. The value is only
                         * used locally while enumerating and is NOT exposed
                         * as interface_index.
                         */
                        let _ = fallback_index;
                        fallback_index =
                            fallback_index.saturating_add(1);

                        devices.push(device);
                    }
                }

                current = device_ref.next;
            }

            pcap_freealldevs(alldevs);

            if devices.is_empty() {
                return Err(DeviceError::DeviceEnumerationFailed);
            }

            Ok(devices)
        }
    }

    #[cfg(not(windows))]
    pub fn enumerate() -> Result<Vec<NpcapDevice>, DeviceError> {
        Err(DeviceError::DeviceEnumerationFailed)
    }

    /// Refreshes the manager from the native Npcap device list.
    pub fn refresh(&mut self) -> Result<(), DeviceError> {
        let devices = Self::enumerate()?;

        self.devices.clear();

        for device in devices {
            self.add(device)?;
        }

        Ok(())
    }
}

#[cfg(windows)]
unsafe fn c_string(
    pointer: *const std::ffi::c_char,
) -> Option<String> {
    if pointer.is_null() {
        return None;
    }

    CStr::from_ptr(pointer)
        .to_str()
        .ok()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub fn normalize_device_name(
    name: OsString,
) -> Option<String> {
    let value =
        name.to_string_lossy().trim().to_string();

    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_device() {
        let device =
            NpcapDevice::new(
                r"\Device\NPF_{TEST}",
            );

        assert!(device.is_some());
    }

    #[test]
    fn rejects_empty_device_name() {
        let device =
            NpcapDevice::new("   ");

        assert!(device.is_none());
    }

    #[test]
    fn device_can_store_interface_index() {
        let mut device =
            NpcapDevice::new(
                r"\Device\NPF_{TEST}",
            )
            .unwrap();

        device.set_interface_index(5);

        assert_eq!(
            device.interface_index,
            Some(5)
        );
    }

    #[test]
    fn zero_interface_index_becomes_none() {
        let mut device =
            NpcapDevice::new(
                r"\Device\NPF_{TEST}",
            )
            .unwrap();

        device.set_interface_index(0);

        assert_eq!(
            device.interface_index,
            None
        );
    }

    #[test]
    fn device_state_changes() {
        let mut device =
            NpcapDevice::new(
                r"\Device\NPF_{TEST}",
            )
            .unwrap();

        device.mark_available();

        assert!(device.is_available());

        device.mark_open();

        assert!(device.is_open());

        device.mark_closed();

        assert_eq!(
            device.state,
            DeviceState::Closed
        );
    }

    #[test]
    fn manager_adds_device() {
        let mut manager =
            DeviceManager::new();

        manager
            .add(
                NpcapDevice::new(
                    r"\Device\NPF_{TEST}",
                )
                .unwrap(),
            )
            .unwrap();

        assert_eq!(
            manager.len(),
            1
        );
    }

    #[test]
    fn manager_does_not_duplicate_device() {
        let mut manager =
            DeviceManager::new();

        let device =
            NpcapDevice::new(
                r"\Device\NPF_{TEST}",
            )
            .unwrap();

        manager
            .add(device.clone())
            .unwrap();

        manager
            .add(device)
            .unwrap();

        assert_eq!(
            manager.len(),
            1
        );
    }

    #[test]
    fn manager_opens_device() {
        let mut manager =
            DeviceManager::new();

        manager
            .add(
                NpcapDevice::new(
                    r"\Device\NPF_{TEST}",
                )
                .unwrap(),
            )
            .unwrap();

        manager
            .open(
                r"\Device\NPF_{TEST}",
            )
            .unwrap();

        assert!(
            manager
                .get(
                    r"\Device\NPF_{TEST}",
                )
                .unwrap()
                .is_open()
        );
    }

    #[test]
    fn manager_rejects_second_open() {
        let mut manager =
            DeviceManager::new();

        manager
            .add(
                NpcapDevice::new(
                    r"\Device\NPF_{TEST}",
                )
                .unwrap(),
            )
            .unwrap();

        manager
            .open(
                r"\Device\NPF_{TEST}",
            )
            .unwrap();

        assert_eq!(
            manager.open(
                r"\Device\NPF_{TEST}",
            ),
            Err(
                DeviceError::DeviceAlreadyOpen
            )
        );
    }

    #[test]
    fn manager_closes_device() {
        let mut manager =
            DeviceManager::new();

        manager
            .add(
                NpcapDevice::new(
                    r"\Device\NPF_{TEST}",
                )
                .unwrap(),
            )
            .unwrap();

        manager
            .open(
                r"\Device\NPF_{TEST}",
            )
            .unwrap();

        manager
            .close(
                r"\Device\NPF_{TEST}",
            )
            .unwrap();

        assert_eq!(
            manager
                .get(
                    r"\Device\NPF_{TEST}",
                )
                .unwrap()
                .state,
            DeviceState::Closed
        );
    }

    #[test]
    fn manager_removes_device() {
        let mut manager =
            DeviceManager::new();

        manager
            .add(
                NpcapDevice::new(
                    r"\Device\NPF_{TEST}",
                )
                .unwrap(),
            )
            .unwrap();

        manager
            .remove(
                r"\Device\NPF_{TEST}",
            )
            .unwrap();

        assert!(manager.is_empty());
    }

    #[test]
    fn normalizes_os_string() {
        let value =
            normalize_device_name(
                OsString::from(" Ethernet "),
            );

        assert_eq!(
            value,
            Some("Ethernet".to_string())
        );
    }
}