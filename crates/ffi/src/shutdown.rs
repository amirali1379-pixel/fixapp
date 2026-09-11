// crates/ffi/src/shutdown.rs

use std::sync::atomic::Ordering;

use network_core::{EngineError, EngineErrorCode, EngineResult};

use crate::engine::EngineRuntime;

impl EngineRuntime {
    pub fn shutdown(&mut self) -> EngineResult<()> {
        if !self.is_initialized() {
            return Err(EngineError::with_message(
                EngineErrorCode::NotInitialized,
                "engine is not initialized",
            ));
        }

        // Stop producers first. Do not continue teardown while a producer
        // failed to stop.
        self.capture_stop()?;
        self.stop_processing_worker();
        self.state.begin_shutdown()?;

        if let Ok(mut gateway) = self.gateway.lock() {
            if gateway.enabled() {
                gateway.stop().map_err(|_| {
                    EngineError::with_message(
                        EngineErrorCode::GatewayNotReady,
                        "failed to stop gateway during shutdown",
                    )
                })?;
            }
        } else {
            return Err(EngineError::with_message(
                EngineErrorCode::InternalError,
                "gateway mutex poisoned during shutdown",
            ));
        }

        self.packet_bus.close();
        loop {
            match self.packet_bus.try_read() {
                Ok(Some(observation)) => {
                    let id = observation.observation_id;
                    if self.packet_bus.release_processing(id).is_err() {
                        self.statistics
                            .total_errors
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    drop(observation);
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }

        if let Ok(mut workers) = self.metadata_workers.lock() {
            workers.stop_all();
        } else {
            return Err(EngineError::with_message(
                EngineErrorCode::InternalError,
                "metadata worker mutex poisoned during shutdown",
            ));
        }

        if let Ok(mut metadata) = self.metadata.lock() {
            metadata.clear();
        } else {
            return Err(EngineError::with_message(
                EngineErrorCode::InternalError,
                "metadata mutex poisoned during shutdown",
            ));
        }

        self.stop_all_native_backends()?;

        if let Ok(mut action) = self.windivert_action.lock() {
            if let Some(mut backend) = action.take() {
                backend.stop().map_err(|_| {
                    EngineError::with_message(
                        EngineErrorCode::BackendStopFailed,
                        "WinDivert action backend failed to stop",
                    )
                })?;
            }
        } else {
            return Err(EngineError::with_message(
                EngineErrorCode::InternalError,
                "WinDivert action mutex poisoned during shutdown",
            ));
        }

        self.set_active_capture_backend(None)?;
        self.set_active_reinjection_backend(None)?;

        if let Ok(mut flow_table) = self.flow_table.lock() {
            let _ = flow_table.clear();
        } else {
            return Err(EngineError::with_message(
                EngineErrorCode::InternalError,
                "flow table mutex poisoned during shutdown",
            ));
        }

        // The runtime is considered shut down only after every owned
        // thread/handle is gone.
        if self
            .processing_thread
            .lock()
            .map_err(|_| {
                EngineError::with_message(
                    EngineErrorCode::InternalError,
                    "processing thread mutex poisoned during shutdown",
                )
            })?
            .is_some()
            || self
                .capture_thread
                .lock()
                .map_err(|_| {
                    EngineError::with_message(
                        EngineErrorCode::InternalError,
                        "capture thread mutex poisoned during shutdown",
                    )
                })?
                .is_some()
            || self
                .windivert_action
                .lock()
                .map_err(|_| {
                    EngineError::with_message(
                        EngineErrorCode::InternalError,
                        "WinDivert action mutex poisoned during shutdown",
                    )
                })?
                .is_some()
            || self
                .npcap_backend
                .lock()
                .map_err(|_| {
                    EngineError::with_message(
                        EngineErrorCode::InternalError,
                        "Npcap backend mutex poisoned during shutdown",
                    )
                })?
                .is_some()
            || self
                .windivert_backend
                .lock()
                .map_err(|_| {
                    EngineError::with_message(
                        EngineErrorCode::InternalError,
                        "WinDivert backend mutex poisoned during shutdown",
                    )
                })?
                .is_some()
            || self
                .wfp_backend
                .lock()
                .map_err(|_| {
                    EngineError::with_message(
                        EngineErrorCode::InternalError,
                        "WFP backend mutex poisoned during shutdown",
                    )
                })?
                .is_some()
            || self
                .iphelper_backend
                .lock()
                .map_err(|_| {
                    EngineError::with_message(
                        EngineErrorCode::InternalError,
                        "IP Helper backend mutex poisoned during shutdown",
                    )
                })?
                .is_some()
            || self
                .etw_backend
                .lock()
                .map_err(|_| {
                    EngineError::with_message(
                        EngineErrorCode::InternalError,
                        "ETW backend mutex poisoned during shutdown",
                    )
                })?
                .is_some()
        {
            return Err(EngineError::with_message(
                EngineErrorCode::BackendStopFailed,
                "shutdown incomplete: native thread or backend handle remains owned by the engine",
            ));
        }

        self.state.shutdown()?;
        self.mark_uninitialized();
        Ok(())
    }

    fn stop_all_native_backends(&self) -> EngineResult<()> {
        let mut failed = false;

        for name in self.backend_manager.names() {
            let lifecycle = match self.backend_manager.runtime_state(&name) {
                Ok(runtime) => runtime.lifecycle,
                Err(_) => {
                    failed = true;
                    continue;
                }
            };
            if !lifecycle.can_stop() {
                continue;
            }

            let result: Result<(), ()> = match name.as_str() {
                "npcap" => match self.npcap_backend.lock() {
                    Ok(mut guard) => match guard.as_mut() {
                        Some(backend) => match backend.stop() {
                            Ok(()) => {
                                guard.take();
                                Ok(())
                            }
                            Err(_) => Err(()),
                        },
                        None => Ok(()),
                    },
                    Err(_) => Err(()),
                },
                "windivert" => match self.windivert_backend.lock() {
                    Ok(mut guard) => match guard.as_mut() {
                        Some(backend) => match backend.stop() {
                            Ok(()) => {
                                guard.take();
                                Ok(())
                            }
                            Err(_) => Err(()),
                        },
                        None => Ok(()),
                    },
                    Err(_) => Err(()),
                },
                "wfp" => match self.wfp_backend.lock() {
                    Ok(mut guard) => match guard.as_mut() {
                        Some(backend) => match backend.close() {
                            Ok(()) => {
                                guard.take();
                                Ok(())
                            }
                            Err(_) => Err(()),
                        },
                        None => Ok(()),
                    },
                    Err(_) => Err(()),
                },
                "iphelper" => match self.iphelper_backend.lock() {
                    Ok(mut guard) => match guard.as_mut() {
                        Some(backend) => match backend.stop() {
                            Ok(()) => {
                                guard.take();
                                Ok(())
                            }
                            Err(_) => Err(()),
                        },
                        None => Ok(()),
                    },
                    Err(_) => Err(()),
                },
                "etw" => match self.etw_backend.lock() {
                    Ok(mut guard) => match guard.as_mut() {
                        Some(backend) => match backend.stop() {
                            Ok(()) => {
                                guard.take();
                                Ok(())
                            }
                            Err(_) => Err(()),
                        },
                        None => Ok(()),
                    },
                    Err(_) => Err(()),
                },
                _ => Ok(()),
            };

            if result.is_ok() {
                if self.backend_manager.mark_stopped(&name).is_err() {
                    failed = true;
                }
            } else {
                let _ = self.backend_manager.set_lifecycle(
                    &name,
                    backend_manager::BackendLifecycle::Failed,
                );
                self.statistics
                    .backend_failures
                    .fetch_add(1, Ordering::Relaxed);
                failed = true;
            }
        }

        if failed {
            Err(EngineError::with_message(
                EngineErrorCode::BackendStopFailed,
                "one or more native backends failed to stop",
            ))
        } else {
            Ok(())
        }
    }

    fn stop_processing_worker(&self) {
        self.processing_stop.store(true, Ordering::SeqCst);
        let handle = match self.processing_thread.lock() {
            Ok(mut guard) => guard.take(),
            Err(_) => None,
        };
        if let Some(handle) = handle {
            let _ = handle.join();
        }
    }
}