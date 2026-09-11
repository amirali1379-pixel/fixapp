// crates/backend-wfp/src/filter.rs

use network_core::{EngineError, EngineErrorCode};
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WfpAction {
    Permit = 0,
    Block = 1,
    Continue = 2,
}

impl WfpAction {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Permit | Self::Block)
    }

    pub fn is_block(self) -> bool {
        self == Self::Block
    }

    pub fn from_fwpm_action_type(v: u32) -> Option<Self> {
        #[cfg(windows)]
        {
            use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;

            match v {
                FWP_ACTION_PERMIT => Some(Self::Permit),
                FWP_ACTION_BLOCK => Some(Self::Block),
                FWP_ACTION_CONTINUE => Some(Self::Continue),
                _ => None,
            }
        }

        #[cfg(not(windows))]
        {
            match v {
                0x1000 => Some(Self::Permit),
                0x1001 => Some(Self::Block),
                0x1002 => Some(Self::Continue),
                _ => None,
            }
        }
    }
}

impl TryFrom<u8> for WfpAction {
    type Error = EngineError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Self::Permit),
            1 => Ok(Self::Block),
            2 => Ok(Self::Continue),
            _ => Err(EngineError::invalid_argument()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfpFilterCondition {
    pub field: String,
    pub value: Vec<u8>,
    pub mask: Option<Vec<u8>>,
}

impl WfpFilterCondition {
    pub fn new(field: impl Into<String>, value: Vec<u8>) -> Result<Self, EngineError> {
        let field = field.into();

        if field.trim().is_empty() || value.is_empty() {
            return Err(EngineError::invalid_argument());
        }

        Ok(Self {
            field,
            value,
            mask: None,
        })
    }

    pub fn with_mask(mut self, mask: Vec<u8>) -> Result<Self, EngineError> {
        if mask.len() != self.value.len() {
            return Err(EngineError::invalid_argument());
        }

        self.mask = Some(mask);
        Ok(self)
    }

    pub fn matches(&self, data: &[u8]) -> bool {
        if data.len() < self.value.len() {
            return false;
        }

        match &self.mask {
            Some(m) => self
                .value
                .iter()
                .zip(m)
                .zip(data)
                .all(|((e, m), a)| (a & m) == (e & m)),
            None => data.get(..self.value.len()) == Some(self.value.as_slice()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfpFilter {
    pub id: u64,
    pub name: String,
    pub layer: String,
    pub action: WfpAction,
    pub conditions: Vec<WfpFilterCondition>,
    pub enabled: bool,
    pub weight: u64,
    kernel_filter_id: u64,
}

impl WfpFilter {
    pub fn new(
        id: u64,
        name: impl Into<String>,
        layer: impl Into<String>,
        action: WfpAction,
    ) -> Result<Self, EngineError> {
        if id == 0 {
            return Err(EngineError::invalid_argument());
        }

        let name = name.into();
        let layer = layer.into();

        if name.trim().is_empty() || layer.trim().is_empty() {
            return Err(EngineError::invalid_argument());
        }

        Ok(Self {
            id,
            name,
            layer,
            action,
            conditions: Vec::new(),
            enabled: true,
            weight: 0,
            kernel_filter_id: 0,
        })
    }

    pub fn add_condition(&mut self, c: WfpFilterCondition) {
        self.conditions.push(c);
    }

    pub fn clear_conditions(&mut self) {
        self.conditions.clear();
    }

    pub fn set_enabled(&mut self, v: bool) {
        self.enabled = v;
    }

    pub fn set_weight(&mut self, v: u64) {
        self.weight = v;
    }

    pub fn matches(&self, p: &[u8]) -> bool {
        self.enabled && self.conditions.iter().all(|c| c.matches(p))
    }

    pub fn evaluate(&self, p: &[u8]) -> Option<WfpAction> {
        self.matches(p).then_some(self.action)
    }

    pub fn condition_count(&self) -> usize {
        self.conditions.len()
    }
}

#[derive(Debug, Default)]
pub struct WfpFilterTable {
    filters: Vec<WfpFilter>,
    engine_handle: Mutex<Option<usize>>,
}

impl WfpFilterTable {
    pub fn new() -> Self {
        Self {
            filters: Vec::new(),
            engine_handle: Mutex::new(None),
        }
    }

    pub fn initialize(&self) -> Result<(), EngineError> {
        let mut slot = self
            .engine_handle
            .lock()
            .map_err(|_| {
                EngineError::backend(
                    EngineErrorCode::InvalidStateTransition,
                    "wfp",
                )
            })?;

        if slot.is_some() {
            return Err(EngineError::already_initialized());
        }

        #[cfg(windows)]
        {
            use std::ptr;
            use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmEngineClose0;

            // `windows-sys 0.52` does not export `FwpmEngineOpen0`.
            // Bind it explicitly from `fwpuclnt.dll`.
            //
            // Signature (from fwpmu.h):
            //
            //     DWORD FwpmEngineOpen0(
            //         const wchar_t* serverName,
            //         UINT32 authnService,
            //         SEC_WINNT_AUTH_IDENTITY_W* authIdentity,
            //         const FWPM_SESSION0* session,
            //         HANDLE* engineHandle);
            unsafe extern "system" {
                fn FwpmEngineOpen0(
                    servername: *const u16,
                    authn_service: u32,
                    auth_identity: *const std::ffi::c_void,
                    session: *const std::ffi::c_void,
                    engine_handle: *mut *mut std::ffi::c_void,
                ) -> u32;
            }

            let mut h: *mut std::ffi::c_void = ptr::null_mut();
            let s = unsafe {
                FwpmEngineOpen0(
                    ptr::null(),
                    0,
                    ptr::null(),
                    ptr::null(),
                    &mut h,
                )
            };

            if s != 0 || h.is_null() {
                return Err(EngineError::backend_native(
                    EngineErrorCode::BackendInitializationFailed,
                    "wfp",
                    s as i32,
                ));
            }

            let h_usize = h as usize;

            if let Err(e) = crate::add_sublayer(h_usize) {
                unsafe {
                    FwpmEngineClose0(h as _);
                }
                return Err(e);
            }

            *slot = Some(h_usize);
            return Ok(());
        }

        #[cfg(not(windows))]
        {
            Err(EngineError::backend(
                EngineErrorCode::BackendUnavailable,
                "wfp",
            ))
        }
    }

    pub fn shutdown(&mut self) -> Result<(), EngineError> {
        self.clear();

        let mut slot = self
            .engine_handle
            .lock()
            .map_err(|_| {
                EngineError::backend(
                    EngineErrorCode::InvalidStateTransition,
                    "wfp",
                )
            })?;

        if let Some(h) = slot.take() {
            #[cfg(windows)]
            {
                use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmEngineClose0;

                let s = unsafe { FwpmEngineClose0(h as _) };
                if s != 0 {
                    return Err(EngineError::backend_native(
                        EngineErrorCode::BackendShutdownFailed,
                        "wfp",
                        s as i32,
                    ));
                }
            }

            #[cfg(not(windows))]
            {
                let _ = h;
            }
        }

        Ok(())
    }

    pub fn insert(&mut self, filter: WfpFilter) -> Result<(), EngineError> {
        if self.filters.iter().any(|f| f.id == filter.id) {
            return Err(EngineError::invalid_argument());
        }

        let h = self
            .engine_handle
            .lock()
            .map_err(|_| {
                EngineError::backend(
                    EngineErrorCode::InvalidStateTransition,
                    "wfp",
                )
            })?
            .ok_or_else(EngineError::not_initialized)?;

        let kid = self.register_in_kernel(h, &filter)?;

        let mut f = filter;
        f.kernel_filter_id = kid;
        self.filters.push(f);
        self.filters.sort_by(|a, b| {
            b.weight
                .cmp(&a.weight)
                .then_with(|| a.id.cmp(&b.id))
        });

        Ok(())
    }

    #[cfg(windows)]
    fn register_in_kernel(
        &self,
        engine: usize,
        filter: &WfpFilter,
    ) -> Result<u64, EngineError> {
        use std::ptr;
        use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
        use windows_sys::core::GUID;

        let layer = crate::layer_keys::resolve(&filter.layer).ok_or_else(|| {
            EngineError::with_message(
                EngineErrorCode::InvalidArgument,
                "unknown WFP layer",
            )
        })?;

        let name: Vec<u16> = filter
            .name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let desc: Vec<u16> = format!("network-engine filter {}", filter.id)
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut backing = Vec::with_capacity(filter.conditions.len());
        for c in &filter.conditions {
            backing.push(NativeCondition::from_condition(c)?);
        }

        let mut conditions: Vec<FWPM_FILTER_CONDITION0> =
            backing.iter().map(|c| c.condition).collect();

        let action_type = match filter.action {
            WfpAction::Permit => FWP_ACTION_PERMIT,
            WfpAction::Block => FWP_ACTION_BLOCK,
            WfpAction::Continue => FWP_ACTION_CONTINUE,
        };

        let mut weight = filter.weight;

        let native = FWPM_FILTER0 {
            filterKey: GUID {
                data1: 0,
                data2: 0,
                data3: 0,
                data4: [0; 8],
            },
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_ptr() as _,
                description: desc.as_ptr() as _,
            },
            flags: if filter.enabled {
                FWPM_FILTER_FLAG_NONE
            } else {
                FWPM_FILTER_FLAG_DISABLED
            },
            providerKey: ptr::null_mut(),
            providerData: FWP_BYTE_BLOB {
                size: 0,
                data: ptr::null_mut(),
            },
            layerKey: layer,
            subLayerKey: crate::management::SUBLAYER_KEY,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous: FWP_VALUE0_0 {
                    uint64: &mut weight,
                },
            },
            numFilterConditions: conditions.len() as u32,
            filterCondition: if conditions.is_empty() {
                ptr::null_mut()
            } else {
                conditions.as_mut_ptr()
            },
            action: FWPM_ACTION0 {
                r#type: action_type,
                Anonymous: FWPM_ACTION0_0 {
                    filterType: GUID {
                        data1: 0,
                        data2: 0,
                        data3: 0,
                        data4: [0; 8],
                    },
                },
            },
            Anonymous: FWPM_FILTER0_0 { rawContext: 0 },
            reserved: ptr::null_mut(),
            filterId: 0,
            // `windows-sys 0.52` does not derive `Default` for `FWP_VALUE0`.
            // Zero-initialize the union instead.
            effectiveWeight: unsafe { std::mem::zeroed() },
        };

        let mut id = 0u64;
        let s = unsafe {
            FwpmFilterAdd0(engine as _, &native, ptr::null_mut(), &mut id)
        };

        if s != 0 {
            return Err(EngineError::backend_native(
                EngineErrorCode::BackendStartFailed,
                "wfp",
                s as i32,
            ));
        }

        Ok(id)
    }

    #[cfg(not(windows))]
    fn register_in_kernel(
        &self,
        _: usize,
        _: &WfpFilter,
    ) -> Result<u64, EngineError> {
        Err(EngineError::backend(
            EngineErrorCode::BackendUnavailable,
            "wfp",
        ))
    }

    pub fn remove(&mut self, id: u64) -> Option<WfpFilter> {
        let i = self.filters.iter().position(|f| f.id == id)?;
        let f = self.filters.remove(i);

        if f.kernel_filter_id != 0 {
            if let Ok(h) = self.engine_handle.lock() {
                if let Some(h) = *h {
                    #[cfg(windows)]
                    unsafe {
                        use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmFilterDeleteById0;
                        let _ = FwpmFilterDeleteById0(h as _, f.kernel_filter_id);
                    }

                    #[cfg(not(windows))]
                    {
                        let _ = h;
                    }
                }
            }
        }

        Some(f)
    }

    pub fn get(&self, id: u64) -> Option<&WfpFilter> {
        self.filters.iter().find(|f| f.id == id)
    }

    pub fn get_mut(&mut self, id: u64) -> Option<&mut WfpFilter> {
        self.filters.iter_mut().find(|f| f.id == id)
    }

    pub fn len(&self) -> usize {
        self.filters.len()
    }

    pub fn is_empty(&self) -> bool {
        self.filters.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &WfpFilter> {
        self.filters.iter()
    }

    pub fn clear(&mut self) {
        let ids: Vec<u64> = self.filters.iter().map(|f| f.id).collect();
        for id in ids {
            let _ = self.remove(id);
        }
    }

    pub fn evaluate(&self, p: &[u8]) -> Option<WfpAction> {
        self.filters.iter().find_map(|f| f.evaluate(p))
    }
}

#[cfg(windows)]
struct NativeCondition {
    condition: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_FILTER_CONDITION0,
    _backing: Option<ConditionBacking>,
}

#[cfg(windows)]
enum ConditionBacking {
    V4(Box<
        windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_V4_ADDR_AND_MASK,
    >),
    V6(Box<
        windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_V6_ADDR_AND_MASK,
    >),
}

#[cfg(windows)]
impl NativeCondition {
    fn from_condition(c: &WfpFilterCondition) -> Result<Self, EngineError> {
        use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;

        let n = c.field.trim().to_ascii_lowercase();

        let (k, t, v, b) = match n.as_str() {
            "protocol" | "ip_protocol" => {
                if c.value.len() != 1 {
                    return Err(EngineError::invalid_argument());
                }

                (
                    FWPM_CONDITION_IP_PROTOCOL,
                    FWP_UINT8,
                    FWP_CONDITION_VALUE0_0 { uint8: c.value[0] },
                    None,
                )
            }

            "local_port" | "ip_local_port" => {
                if c.value.len() != 2 {
                    return Err(EngineError::invalid_argument());
                }

                (
                    FWPM_CONDITION_IP_LOCAL_PORT,
                    FWP_UINT16,
                    FWP_CONDITION_VALUE0_0 {
                        uint16: u16::from_ne_bytes([c.value[0], c.value[1]]),
                    },
                    None,
                )
            }

            "remote_port" | "ip_remote_port" => {
                if c.value.len() != 2 {
                    return Err(EngineError::invalid_argument());
                }

                (
                    FWPM_CONDITION_IP_REMOTE_PORT,
                    FWP_UINT16,
                    FWP_CONDITION_VALUE0_0 {
                        uint16: u16::from_ne_bytes([c.value[0], c.value[1]]),
                    },
                    None,
                )
            }

            "direction" => {
                if c.value.len() != 1 {
                    return Err(EngineError::invalid_argument());
                }

                (
                    FWPM_CONDITION_DIRECTION,
                    FWP_UINT32,
                    FWP_CONDITION_VALUE0_0 {
                        uint32: c.value[0] as u32,
                    },
                    None,
                )
            }

            "local_address" | "ip_local_address" => {
                address(FWPM_CONDITION_IP_LOCAL_ADDRESS, c)?
            }

            "remote_address" | "ip_remote_address" => {
                address(FWPM_CONDITION_IP_REMOTE_ADDRESS, c)?
            }

            "local_address_v4" | "ip_local_address_v4" => {
                address(FWPM_CONDITION_IP_LOCAL_ADDRESS_V4, c)?
            }

            "remote_address_v4" | "ip_remote_address_v4" => {
                address(FWPM_CONDITION_IP_REMOTE_ADDRESS_V4, c)?
            }

            "local_address_v6" | "ip_local_address_v6" => {
                address(FWPM_CONDITION_IP_LOCAL_ADDRESS_V6, c)?
            }

            "remote_address_v6" | "ip_remote_address_v6" => {
                address(FWPM_CONDITION_IP_REMOTE_ADDRESS_V6, c)?
            }

            _ => {
                return Err(EngineError::with_message(
                    EngineErrorCode::InvalidArgument,
                    "unsupported WFP filter condition",
                ));
            }
        };

        Ok(Self {
            condition: FWPM_FILTER_CONDITION0 {
                fieldKey: k,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: t,
                    Anonymous: v,
                },
            },
            _backing: b,
        })
    }
}

#[cfg(windows)]
fn address(
    k: windows_sys::core::GUID,
    c: &WfpFilterCondition,
) -> Result<
    (
        windows_sys::core::GUID,
        windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_DATA_TYPE,
        windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0,
        Option<ConditionBacking>,
    ),
    EngineError,
> {
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;

    match c.value.len() {
        4 => {
            let m = c.mask.as_deref().unwrap_or(&[0xff; 4]);
            if m.len() != 4 {
                return Err(EngineError::invalid_argument());
            }

            let b = Box::new(FWP_V4_ADDR_AND_MASK {
                addr: u32::from_ne_bytes(c.value[..4].try_into().unwrap()),
                mask: u32::from_ne_bytes(m.try_into().unwrap()),
            });

            let p = (&*b) as *const _ as *mut _;

            Ok((
                k,
                FWP_V4_ADDR_MASK,
                FWP_CONDITION_VALUE0_0 { v4AddrMask: p },
                Some(ConditionBacking::V4(b)),
            ))
        }

        16 => {
            let m = c.mask.as_deref().unwrap_or(&[0xff; 16]);
            if m.len() != 16 {
                return Err(EngineError::invalid_argument());
            }

            let b = Box::new(FWP_V6_ADDR_AND_MASK {
                addr: c.value[..16].try_into().unwrap(),
                prefixLength: prefix(m).ok_or_else(EngineError::invalid_argument)?,
            });

            let p = (&*b) as *const _ as *mut _;

            Ok((
                k,
                FWP_V6_ADDR_MASK,
                FWP_CONDITION_VALUE0_0 { v6AddrMask: p },
                Some(ConditionBacking::V6(b)),
            ))
        }

        _ => Err(EngineError::invalid_argument()),
    }
}

#[cfg(windows)]
fn prefix(m: &[u8]) -> Option<u8> {
    let mut n = 0;
    let mut z = false;

    for b in m {
        for bit in (0..8).rev() {
            if b & (1 << bit) != 0 {
                if z {
                    return None;
                }
                n += 1;
            } else {
                z = true;
            }
        }
    }

    Some(n)
}