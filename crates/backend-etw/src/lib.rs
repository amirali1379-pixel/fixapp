pub mod events;
pub mod provider;

pub use events::{
    EtwEvent,
    EtwEventId,
    EtwEventKind,
    EtwSeverity,
};

pub use provider::{
    EtwError,
    EtwProvider,
};

#[derive(Debug)]
pub struct EtwBackend {
    provider: EtwProvider,
    running: bool,
}

impl EtwBackend {
    pub fn new(
        provider: EtwProvider,
    ) -> Self {
        Self {
            provider,
            running: false,
        }
    }

    pub fn start(
        &mut self,
    ) -> Result<(), EtwError> {
        if self.running {
            return Ok(());
        }

        self.provider.start()?;
        self.running = true;

        Ok(())
    }

    pub fn stop(
        &mut self,
    ) -> Result<(), EtwError> {
        if !self.running {
            return Ok(());
        }

        self.provider.stop()?;
        self.running = false;

        Ok(())
    }

    pub fn is_running(&self) -> bool {
        self.running
    }

    pub fn provider(&self) -> &EtwProvider {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut EtwProvider {
        &mut self.provider
    }
}

impl Default for EtwBackend {
    fn default() -> Self {
        Self::new(EtwProvider::default())
    }
}

impl Drop for EtwBackend {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_starts_and_stops() {
        let provider = EtwProvider::new(
            "network-engine",
        );

        let mut backend =
            EtwBackend::new(provider);

        assert!(!backend.is_running());

        assert!(
            backend.start().is_ok()
        );

        assert!(backend.is_running());

        assert!(
            backend.stop().is_ok()
        );

        assert!(!backend.is_running());
    }

    #[test]
    fn repeated_start_is_safe() {
        let provider = EtwProvider::new(
            "network-engine",
        );

        let mut backend =
            EtwBackend::new(provider);

        backend.start().unwrap();
        backend.start().unwrap();

        assert!(backend.is_running());
    }

    #[test]
    fn repeated_stop_is_safe() {
        let provider = EtwProvider::new(
            "network-engine",
        );

        let mut backend =
            EtwBackend::new(provider);

        backend.stop().unwrap();
        backend.stop().unwrap();

        assert!(!backend.is_running());
    }
}