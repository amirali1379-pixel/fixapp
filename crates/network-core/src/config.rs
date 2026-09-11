use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::EngineError;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EngineConfig {
    pub queue_capacity: usize,
    pub pool_max_size: usize,
    pub buffer_capacity: usize,
    pub max_flows: usize,
    pub flow_timeout_secs: u64,

    pub enable_gateway: bool,

    pub capture_enabled: bool,
    pub interception_enabled: bool,

    pub enable_wfp: bool,
    pub enable_windivert: bool,
    pub enable_npcap: bool,
    pub enable_iphelper: bool,
    pub enable_etw: bool,

    pub log_level: String,

    /// Maximum packet size accepted by the Engine.
    pub max_packet_size: usize,

    /// Maximum number of observations waiting in processing queues.
    pub max_pending_observations: usize,

    /// Maximum time a shutdown is allowed to take.
    pub shutdown_timeout_ms: u64,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            queue_capacity: 4096,
            pool_max_size: 4096,
            buffer_capacity: 65535,
            max_flows: 100_000,
            flow_timeout_secs: 300,

            enable_gateway: false,

            capture_enabled: false,
            interception_enabled: false,

            enable_wfp: true,
            enable_windivert: true,
            enable_npcap: true,
            enable_iphelper: true,
            enable_etw: true,

            log_level: "info".to_owned(),

            max_packet_size: 65_535,
            max_pending_observations: 4096,

            shutdown_timeout_ms: 5000,
        }
    }
}

impl EngineConfig {
    /// Validate configuration before the Engine starts.
    pub fn validate(&self) -> Result<(), EngineError> {
        if self.queue_capacity == 0 {
            return Err(EngineError::with_message(
                crate::error::EngineErrorCode::ConfigurationInvalid,
                "queue_capacity must be greater than zero",
            ));
        }

        if self.pool_max_size == 0 {
            return Err(EngineError::with_message(
                crate::error::EngineErrorCode::ConfigurationInvalid,
                "pool_max_size must be greater than zero",
            ));
        }

        if self.buffer_capacity == 0 {
            return Err(EngineError::with_message(
                crate::error::EngineErrorCode::ConfigurationInvalid,
                "buffer_capacity must be greater than zero",
            ));
        }

        if self.max_flows == 0 {
            return Err(EngineError::with_message(
                crate::error::EngineErrorCode::ConfigurationInvalid,
                "max_flows must be greater than zero",
            ));
        }

        if self.flow_timeout_secs == 0 {
            return Err(EngineError::with_message(
                crate::error::EngineErrorCode::ConfigurationInvalid,
                "flow_timeout_secs must be greater than zero",
            ));
        }

        if self.max_packet_size == 0 {
            return Err(EngineError::with_message(
                crate::error::EngineErrorCode::ConfigurationInvalid,
                "max_packet_size must be greater than zero",
            ));
        }

        if self.max_packet_size > u32::MAX as usize {
            return Err(EngineError::with_message(
                crate::error::EngineErrorCode::ConfigurationInvalid,
                "max_packet_size exceeds u32 packet length limit",
            ));
        }

        if self.max_pending_observations == 0 {
            return Err(EngineError::with_message(
                crate::error::EngineErrorCode::ConfigurationInvalid,
                "max_pending_observations must be greater than zero",
            ));
        }

        if self.shutdown_timeout_ms == 0 {
            return Err(EngineError::with_message(
                crate::error::EngineErrorCode::ConfigurationInvalid,
                "shutdown_timeout_ms must be greater than zero",
            ));
        }

        if self.pool_max_size < self.queue_capacity {
            return Err(EngineError::with_message(
                crate::error::EngineErrorCode::ConfigurationInvalid,
                "pool_max_size must be >= queue_capacity",
            ));
        }

        if self.max_pending_observations < self.queue_capacity {
            return Err(EngineError::with_message(
                crate::error::EngineErrorCode::ConfigurationInvalid,
                "max_pending_observations must be >= queue_capacity",
            ));
        }

        if !matches!(
            self.log_level.as_str(),
            "trace" | "debug" | "info" | "warn" | "error"
        ) {
            return Err(EngineError::with_message(
                crate::error::EngineErrorCode::ConfigurationInvalid,
                "log_level must be trace, debug, info, warn, or error",
            ));
        }

        Ok(())
    }

    /// Load configuration from TOML text.
    pub fn from_toml(text: &str) -> Result<Self, EngineError> {
        let config: Self = toml::from_str(text).map_err(|error| {
            EngineError::with_message(
                crate::error::EngineErrorCode::ConfigurationInvalid,
                format!("invalid TOML configuration: {error}"),
            )
        })?;

        config.validate()?;

        Ok(config)
    }

    /// Load configuration from a TOML file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, EngineError> {
        let path = path.as_ref();

        let text = std::fs::read_to_string(path).map_err(|error| {
            EngineError::with_message(
                crate::error::EngineErrorCode::ConfigurationInvalid,
                format!(
                    "failed to read configuration '{}': {error}",
                    path.display()
                ),
            )
        })?;

        Self::from_toml(&text)
    }

    /// Serialize the configuration as TOML.
    pub fn to_toml(&self) -> Result<String, EngineError> {
        self.validate()?;

        toml::to_string_pretty(self).map_err(|error| {
            EngineError::with_message(
                crate::error::EngineErrorCode::ConfigurationInvalid,
                format!("failed to serialize configuration: {error}"),
            )
        })
    }

    /// Validate and normalize configuration.
    ///
    /// This does not enable any backend or change runtime state.
    pub fn normalized(mut self) -> Result<Self, EngineError> {
        self.log_level = self.log_level.trim().to_ascii_lowercase();

        self.validate()?;

        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_configuration_is_valid() {
        let config = EngineConfig::default();

        assert!(config.validate().is_ok());
    }

    #[test]
    fn zero_queue_is_rejected() {
        let mut config = EngineConfig::default();
        config.queue_capacity = 0;

        assert!(config.validate().is_err());
    }

    #[test]
    fn zero_pool_is_rejected() {
        let mut config = EngineConfig::default();
        config.pool_max_size = 0;

        assert!(config.validate().is_err());
    }

    #[test]
    fn invalid_log_level_is_rejected() {
        let mut config = EngineConfig::default();
        config.log_level = "invalid".to_owned();

        assert!(config.validate().is_err());
    }

    #[test]
    fn toml_roundtrip_works() {
        let config = EngineConfig::default();

        let text = config.to_toml().unwrap();
        let restored = EngineConfig::from_toml(&text).unwrap();

        assert_eq!(restored.queue_capacity, config.queue_capacity);
        assert_eq!(restored.pool_max_size, config.pool_max_size);
        assert_eq!(restored.buffer_capacity, config.buffer_capacity);
        assert_eq!(restored.max_flows, config.max_flows);
        assert_eq!(restored.enable_gateway, config.enable_gateway);
    }

    #[test]
    fn malformed_toml_is_rejected() {
        let result = EngineConfig::from_toml(
            "queue_capacity = [this is not valid toml",
        );

        assert!(result.is_err());
    }

    #[test]
    fn normalized_log_level_is_lowercase() {
        let mut config = EngineConfig::default();
        config.log_level = "  DEBUG  ".to_owned();

        let config = config.normalized().unwrap();

        assert_eq!(config.log_level, "debug");
    }

    #[test]
    fn pool_cannot_be_smaller_than_queue() {
        let mut config = EngineConfig::default();
        config.pool_max_size = config.queue_capacity - 1;

        assert!(config.validate().is_err());
    }

    #[test]
    fn pending_observations_cannot_be_smaller_than_queue() {
        let mut config = EngineConfig::default();
        config.max_pending_observations = config.queue_capacity - 1;

        assert!(config.validate().is_err());
    }
}