// crates/backend-contracts/src/kind.rs

#![forbid(unsafe_code)]

/// Well-known native backend identities.
///
/// `BackendKind` is a design-time identity, not a runtime handle.
/// It does NOT represent backend lifecycle, health, or capability
/// availability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackendKind {
    Npcap,
    WinDivert,
    Wfp,
    IpHelper,
    Etw,
}

impl BackendKind {
    /// Stable backend name used by `BackendDescriptor::name`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Npcap => "npcap",
            Self::WinDivert => "windivert",
            Self::Wfp => "wfp",
            Self::IpHelper => "iphelper",
            Self::Etw => "etw",
        }
    }

    /// Human-readable description.
    pub const fn description(self) -> &'static str {
        match self {
            Self::Npcap => "Npcap Layer-2/raw packet acquisition backend",
            Self::WinDivert => {
                "WinDivert IP-layer interception and packet-action backend"
            }
            Self::Wfp => "Windows Filtering Platform backend",
            Self::IpHelper => "Windows IP Helper network-state backend",
            Self::Etw => "Windows ETW diagnostics and telemetry backend",
        }
    }

    /// All known backend kinds in deterministic order.
    pub const fn all() -> &'static [Self] {
        &[
            Self::Npcap,
            Self::WinDivert,
            Self::Wfp,
            Self::IpHelper,
            Self::Etw,
        ]
    }

    /// Resolves a `BackendKind` from its stable name.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "npcap" => Some(Self::Npcap),
            "windivert" => Some(Self::WinDivert),
            "wfp" => Some(Self::Wfp),
            "iphelper" => Some(Self::IpHelper),
            "etw" => Some(Self::Etw),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_kinds_have_unique_names() {
        let mut names: Vec<&str> =
            BackendKind::all().iter().map(|k| k.name()).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), BackendKind::all().len());
    }

    #[test]
    fn from_name_round_trips() {
        for kind in BackendKind::all() {
            assert_eq!(BackendKind::from_name(kind.name()), Some(*kind));
        }
    }

    #[test]
    fn unknown_name_returns_none() {
        assert_eq!(BackendKind::from_name("unknown"), None);
    }
}