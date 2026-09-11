// dll/network-engine/src/backends.rs

#![forbid(unsafe_code)]

use std::sync::atomic::Ordering;
use network_core::{EngineError, EngineErrorCode, EngineResult};
use backend_manager::{BackendCapability, BackendDescriptor, BackendLifecycle};
use crate::engine::EngineRuntime;
use crate::load_balancer::{BackendLoad, LoadBalancerStats};

impl EngineRuntime {
    pub fn register_backend(&self, descriptor: BackendDescriptor) -> EngineResult<()> {
        self.require_running()?;
        self.backend_manager.register(descriptor).map_err(|error| {
            self.statistics.total_errors.fetch_add(1, Ordering::Relaxed);
            error
        })
    }

    /// Starts the real native capability first, then commits the manager
    /// lifecycle to Running. Every failure after the Starting transition is
    /// converted to Failed so the manager can never remain stuck in Starting.
    pub fn start_backend(&self, name: &str) -> EngineResult<()> {
        self.require_running()?;
        self.backend_manager.start(name, self.packet_bus.clone())?;

        let native_result: EngineResult<()> = (|| {
            match name {
                "npcap" => {
                    let mut guard = self.npcap_backend.lock().map_err(|_| EngineError::with_message(
                        EngineErrorCode::InternalError,
                        "Npcap backend mutex poisoned",
                    ))?;
                    if guard.is_none() {
                        *guard = Some(backend_npcap::NpcapBackend::new());
                    }
                    guard.as_mut().expect("Npcap backend initialized").start().map_err(|error| EngineError::with_message(
                        EngineErrorCode::BackendInitializationFailed,
                        format!("Npcap start failed: {:?}", error),
                    ))
                }
                "windivert" => {
                    let mut guard = self.windivert_backend.lock().map_err(|_| EngineError::with_message(
                        EngineErrorCode::InternalError,
                        "WinDivert backend mutex poisoned",
                    ))?;
                    if guard.is_none() {
                        let config = backend_windivert::WinDivertConfig::new(
                            "true",
                            backend_windivert::WinDivertLayer::Network,
                        ).map_err(|_| EngineError::backend_init_failed())?;
                        *guard = Some(backend_windivert::WinDivertBackend::new(config));
                    }
                    guard.as_mut().expect("WinDivert backend initialized").start().map_err(|error| EngineError::with_message(
                        EngineErrorCode::BackendInitializationFailed,
                        format!("WinDivert start failed: {:?}", error),
                    ))
                }
                "wfp" => {
                    let mut guard = self.wfp_backend.lock().map_err(|_| EngineError::with_message(
                        EngineErrorCode::InternalError,
                        "WFP backend mutex poisoned",
                    ))?;
                    if guard.is_none() {
                        *guard = Some(backend_wfp::WfpEngine::new());
                    }
                    guard.as_mut().expect("WFP backend initialized").open()
                }
                "iphelper" => {
                    let mut guard = self.iphelper_backend.lock().map_err(|_| EngineError::with_message(
                        EngineErrorCode::InternalError,
                        "IP Helper backend mutex poisoned",
                    ))?;
                    if guard.is_none() {
                        *guard = Some(backend_iphelper::IpHelperBackend::new());
                    }
                    guard.as_mut().expect("IP Helper backend initialized").start().map_err(|error| EngineError::with_message(
                        EngineErrorCode::BackendInitializationFailed,
                        format!("IP Helper start failed: {:?}", error),
                    ))
                }
                "etw" => {
                    let mut guard = self.etw_backend.lock().map_err(|_| EngineError::with_message(
                        EngineErrorCode::InternalError,
                        "ETW backend mutex poisoned",
                    ))?;
                    if guard.is_none() {
                        *guard = Some(backend_etw::EtwBackend::new(
                            backend_etw::EtwProvider::new("network-engine"),
                        ));
                    }
                    guard.as_mut().expect("ETW backend initialized").start().map_err(|error| EngineError::with_message(
                        EngineErrorCode::BackendInitializationFailed,
                        format!("ETW start failed: {:?}", error),
                    ))
                }
                _ => Ok(()),
            }
        })();

        if let Err(error) = native_result {
            let _ = self.backend_manager.set_lifecycle(name, BackendLifecycle::Failed);
            self.statistics.backend_failures.fetch_add(1, Ordering::Relaxed);
            return Err(error);
        }

        self.backend_manager.mark_running(name)?;
        let _ = self.backend_manager.record_success(name);
        Ok(())
    }

    /// Stops the native capability first, then commits the manager lifecycle.
    /// A built-in backend that has no native instance is an error, because
    /// claiming a clean stop would desynchronise Engine and native state.
    /// Every failure after the Stopping transition becomes Failed.
    pub fn stop_backend(&self, name: &str) -> EngineResult<()> {
        self.require_running()?;
        self.backend_manager.stop(name)?;

        let native_result: EngineResult<()> = (|| {
            match name {
                "npcap" => {
                    let mut guard = self.npcap_backend.lock().map_err(|_| EngineError::with_message(
                        EngineErrorCode::InternalError,
                        "Npcap backend mutex poisoned",
                    ))?;
                    let backend = guard.as_mut().ok_or_else(|| EngineError::with_message(
                        EngineErrorCode::BackendShutdownFailed,
                        "Npcap backend has no native instance while lifecycle is active",
                    ))?;
                    backend.stop().map_err(|error| EngineError::with_message(
                        EngineErrorCode::BackendShutdownFailed,
                        format!("Npcap stop failed: {:?}", error),
                    ))
                }
                "windivert" => {
                    let mut guard = self.windivert_backend.lock().map_err(|_| EngineError::with_message(
                        EngineErrorCode::InternalError,
                        "WinDivert backend mutex poisoned",
                    ))?;
                    let backend = guard.as_mut().ok_or_else(|| EngineError::with_message(
                        EngineErrorCode::BackendShutdownFailed,
                        "WinDivert backend has no native instance while lifecycle is active",
                    ))?;
                    backend.stop().map_err(|error| EngineError::with_message(
                        EngineErrorCode::BackendShutdownFailed,
                        format!("WinDivert stop failed: {:?}", error),
                    ))
                }
                "wfp" => {
                    let mut guard = self.wfp_backend.lock().map_err(|_| EngineError::with_message(
                        EngineErrorCode::InternalError,
                        "WFP backend mutex poisoned",
                    ))?;
                    let backend = guard.as_mut().ok_or_else(|| EngineError::with_message(
                        EngineErrorCode::BackendShutdownFailed,
                        "WFP backend has no native instance while lifecycle is active",
                    ))?;
                    backend.close()
                }
                "iphelper" => {
                    let mut guard = self.iphelper_backend.lock().map_err(|_| EngineError::with_message(
                        EngineErrorCode::InternalError,
                        "IP Helper backend mutex poisoned",
                    ))?;
                    let backend = guard.as_mut().ok_or_else(|| EngineError::with_message(
                        EngineErrorCode::BackendShutdownFailed,
                        "IP Helper backend has no native instance while lifecycle is active",
                    ))?;
                    backend.stop().map_err(|error| EngineError::with_message(
                        EngineErrorCode::BackendShutdownFailed,
                        format!("IP Helper stop failed: {:?}", error),
                    ))
                }
                "etw" => {
                    let mut guard = self.etw_backend.lock().map_err(|_| EngineError::with_message(
                        EngineErrorCode::InternalError,
                        "ETW backend mutex poisoned",
                    ))?;
                    let backend = guard.as_mut().ok_or_else(|| EngineError::with_message(
                        EngineErrorCode::BackendShutdownFailed,
                        "ETW backend has no native instance while lifecycle is active",
                    ))?;
                    backend.stop().map_err(|error| EngineError::with_message(
                        EngineErrorCode::BackendShutdownFailed,
                        format!("ETW stop failed: {:?}", error),
                    ))
                }
                _ => Ok(()),
            }
        })();

        if let Err(error) = native_result {
            let _ = self.backend_manager.set_lifecycle(name, BackendLifecycle::Failed);
            self.statistics.backend_failures.fetch_add(1, Ordering::Relaxed);
            return Err(error);
        }

        self.backend_manager.mark_stopped(name)?;

        // Forget the backend's Load Balancer counters; the backend is no
        // longer a candidate for work distribution.
        self.load_balancer.forget(name);

        if self.active_capture_backend()?.as_deref() == Some(name) {
            self.set_active_capture_backend(None)?;
        }
        if self.active_reinjection_backend()?.as_deref() == Some(name) {
            self.set_active_reinjection_backend(None)?;
        }

        Ok(())
    }

    pub fn restart_backend(&self, name: &str) -> EngineResult<()> {
        self.require_running()?;
        let lifecycle = self.backend_manager.runtime_state(name)?.lifecycle;

        match lifecycle {
            BackendLifecycle::Running | BackendLifecycle::Degraded => {
                self.stop_backend(name)?;
                self.start_backend(name)
            }
            BackendLifecycle::Failed | BackendLifecycle::Stopped | BackendLifecycle::Disabled => {
                self.start_backend(name)
            }
            BackendLifecycle::Starting | BackendLifecycle::Stopping => Err(EngineError::with_message(
                EngineErrorCode::ConcurrentOperation,
                format!("backend '{}' is already transitioning", name),
            )),
        }
    }

    pub fn backend_supports(&self, name: &str, capability: BackendCapability) -> EngineResult<bool> {
        self.require_running()?;
        self.backend_manager.supports(name, capability)
    }

    pub fn backend_lifecycle(&self, name: &str) -> EngineResult<BackendLifecycle> {
        self.require_running()?;
        Ok(self.backend_manager.runtime_state(name)?.lifecycle)
    }

    /// Returns the current Load Balancer load of a backend.
    pub fn backend_load(&self, name: &str) -> BackendLoad {
        self.load_balancer.load_of(name)
    }

    /// Returns an aggregate Load Balancer statistics snapshot.
    pub fn load_balancer_stats(&self) -> LoadBalancerStats {
        self.load_balancer.stats()
    }

    pub fn isolate_failed_backend(&self, name: &str) -> EngineResult<()> {
        self.require_running()?;

        let lifecycle = self.backend_manager.runtime_state(name)?.lifecycle;
        match lifecycle {
            BackendLifecycle::Running | BackendLifecycle::Degraded => self.stop_backend(name)?,
            BackendLifecycle::Failed | BackendLifecycle::Stopped | BackendLifecycle::Disabled => {}
            BackendLifecycle::Starting | BackendLifecycle::Stopping => {
                return Err(EngineError::with_message(
                    EngineErrorCode::ConcurrentOperation,
                    format!("backend '{}' is transitioning and cannot be isolated yet", name),
                ))
            }
        }

        Ok(())
    }

    /// Performs the complete Engine-side capture failover transition:
    /// isolate the failed backend, select a healthy compatible alternative,
    /// and publish that backend as the active capture route.
    ///
    /// The native capture provider remains responsible for its own capture
    /// session configuration. This method never fabricates an interface or
    /// capture configuration that is not present in the backend contract.
    pub fn failover_capture_backend(&self, failed_backend: &str) -> EngineResult<String> {
        self.require_running()?;
        self.isolate_failed_backend(failed_backend)?;

        let alternative = backend_manager::select_healthy_backend_for_failover(
            &self.backend_manager,
            BackendCapability::Capture,
            failed_backend,
        )
        .ok_or_else(|| {
            EngineError::with_message(
                EngineErrorCode::CapabilityUnavailable,
                "no healthy backend provides a sufficient capture capability for failover",
            )
        })?;

        self.set_active_capture_backend(Some(alternative.clone()))?;
        self.statistics.backend_failovers.fetch_add(1, Ordering::Relaxed);
        Ok(alternative)
    }

    /// Performs the complete Engine-side reinjection failover transition:
    /// isolate the failed backend, select a healthy compatible alternative,
    /// and publish that backend as the active reinjection route.
    ///
    /// Native action ownership remains with the concrete backend that actually
    /// implements the Reinjection capability.
    pub fn failover_reinjection_backend(&self, failed_backend: &str) -> EngineResult<String> {
        self.require_running()?;
        self.isolate_failed_backend(failed_backend)?;

        let alternative = backend_manager::select_healthy_backend_for_failover(
            &self.backend_manager,
            BackendCapability::Reinjection,
            failed_backend,
        )
        .ok_or_else(|| {
            EngineError::with_message(
                EngineErrorCode::CapabilityUnavailable,
                "no healthy backend provides a sufficient reinjection capability for failover",
            )
        })?;

        self.set_active_reinjection_backend(Some(alternative.clone()))?;
        self.statistics.backend_failovers.fetch_add(1, Ordering::Relaxed);
        Ok(alternative)
    }

    pub fn backend_names(&self) -> Vec<String> {
        self.backend_manager.names()
    }
}