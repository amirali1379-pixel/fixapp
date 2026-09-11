use crate::handle::{WinDivertConfig, WinDivertError, WinDivertLayer};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureConfig {
    pub filter: String,
    pub layer: String,
    pub priority: i16,
}

impl CaptureConfig {
    pub fn new(filter: &str) -> Self {
        Self {
            filter: filter.trim().to_string(),
            layer: "network".to_string(),
            priority: 0,
        }
    }

    pub fn with_layer(mut self, layer: &str) -> Self {
        let layer = layer.trim();
        if !layer.is_empty() {
            self.layer = layer.to_string();
        }
        self
    }

    pub fn with_priority(mut self, priority: i16) -> Self {
        self.priority = priority;
        self
    }

    pub fn is_valid(&self) -> bool {
        !self.filter.is_empty() && !self.layer.is_empty() && self.layer_kind().is_some()
    }

    pub fn layer_kind(&self) -> Option<WinDivertLayer> {
        match self.layer.trim().to_ascii_lowercase().as_str() {
            "network" => Some(WinDivertLayer::Network),
            "network-forward" | "network_forward" | "networkforward" => {
                Some(WinDivertLayer::NetworkForward)
            }
            "flow" => Some(WinDivertLayer::Flow),
            "socket" => Some(WinDivertLayer::Socket),
            "reflect" => Some(WinDivertLayer::Reflect),
            _ => None,
        }
    }

    pub fn into_handle_config(self) -> Result<WinDivertConfig, WinDivertError> {
        let layer = self
            .layer_kind()
            .ok_or(WinDivertError::InvalidOperation)?;
        let mut config = WinDivertConfig::new(self.filter, layer)?;
        config.priority = self.priority;
        Ok(config)
    }
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self::new("true")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_network_layer_to_handle_config() {
        let config = CaptureConfig::new("tcp")
            .with_priority(10)
            .into_handle_config()
            .unwrap();

        assert_eq!(config.layer, WinDivertLayer::Network);
        assert_eq!(config.priority, 10);
        assert_eq!(config.filter, "tcp");
    }

    #[test]
    fn rejects_unknown_layer() {
        let config = CaptureConfig::new("true").with_layer("unknown");
        assert!(!config.is_valid());
        assert_eq!(config.layer_kind(), None);
        assert!(matches!(
            config.into_handle_config(),
            Err(WinDivertError::InvalidOperation)
        ));
    }
}
