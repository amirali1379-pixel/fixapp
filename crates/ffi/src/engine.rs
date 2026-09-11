// Engine runtime object.
//
// The Engine is the runtime data owner and orchestrator.
// The stable C ABI surface lives in `crate::api`.

#![forbid(unsafe_code)]

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, OnceLock};

use network_core::metrics::EngineMetrics;
use network_core::statistics::EngineStatistics;
use network_core::{
    EngineResult, EngineState,
    PacketActionPolicyConfig,
};
use packet_bus::{BufferPool, PacketBus};
use flow_engine::FlowTable;
use correlation::dedup::DedupFilter;
use correlation::matcher::ObservationMatcher;
use metadata_engine::WorkerPool;
use backend_manager::BackendManager;
use network_state::NetworkState;
use gateway_capability::GatewayCapability;
use backend_windivert::{WinDivertBackend, WinDivertConfig, WinDivertError, WinDivertLayer};
use backend_npcap::NpcapBackend;
use backend_wfp::WfpEngine;
use backend_iphelper::IpHelperBackend;
use backend_etw::EtwBackend;

use crate::coordination::MultiBackendCoordinator;
use crate::load_balancer::LoadBalancer;
use crate::metrics::MetricsView;

pub const DEFAULT_METADATA_WORKERS: usize = 2;
pub const DEFAULT_DEDUP_CAPACITY: usize = 65_536;

pub struct EngineRuntime {
    pub state: Arc<EngineState>,
    pub packet_bus: Arc<PacketBus>,
    pub buffer_pool: Arc<BufferPool>,
    pub flow_table: Arc<Mutex<FlowTable>>,
    pub matcher: ObservationMatcher,
    pub dedup: Arc<DedupFilter>,
    pub metadata_workers: Arc<Mutex<WorkerPool>>,
    pub metadata: Arc<Mutex<network_core::metadata::MetadataStore>>,
    pub backend_manager: Arc<BackendManager>,
    pub coordinator: Arc<MultiBackendCoordinator>,
    pub load_balancer: Arc<LoadBalancer>,
    pub network_state: Arc<Mutex<NetworkState>>,
    pub gateway: Arc<Mutex<GatewayCapability>>,
    pub statistics: Arc<EngineStatistics>,
    pub metrics: Arc<EngineMetrics>,
    pub packet_policy: Mutex<PacketActionPolicyConfig>,
    pub processing_stop: Arc<AtomicBool>,
    pub processing_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    pub capture_stop: Arc<AtomicBool>,
    pub capture_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    pub windivert_action: Mutex<Option<WinDivertBackend>>,
    pub npcap_backend: Mutex<Option<NpcapBackend>>,
    pub windivert_backend: Mutex<Option<WinDivertBackend>>,
    pub wfp_backend: Mutex<Option<WfpEngine>>,
    pub iphelper_backend: Mutex<Option<IpHelperBackend>>,
    pub etw_backend: Mutex<Option<EtwBackend>>,
    pub active_capture_backend: Mutex<Option<String>>,
    pub active_reinjection_backend: Mutex<Option<String>>,
    initialized: bool,
}

impl EngineRuntime {
    pub fn new(
        queue_capacity: usize,
        pool_max_size: usize,
        buffer_capacity: usize,
        max_flows: usize,
    ) -> Self {
        let buffer_pool = BufferPool::new(pool_max_size, buffer_capacity)
            .expect("EngineRuntime::new requires positive pool and buffer capacities");

        let backend_manager = Arc::new(BackendManager::new());
        let coordinator =
            Arc::new(MultiBackendCoordinator::new(Arc::clone(&backend_manager)));
        let load_balancer =
            Arc::new(LoadBalancer::new(Arc::clone(&backend_manager)));

        Self {
            state: Arc::new(EngineState::new()),
            packet_bus: Arc::new(PacketBus::new(queue_capacity)),
            buffer_pool: Arc::new(buffer_pool),
            flow_table: Arc::new(Mutex::new(
                FlowTable::with_defaults(max_flows).unwrap_or_default(),
            )),
            matcher: ObservationMatcher,
            dedup: Arc::new(DedupFilter::new(DEFAULT_DEDUP_CAPACITY)),
            metadata_workers: Arc::new(Mutex::new(WorkerPool::new(DEFAULT_METADATA_WORKERS))),
            metadata: Arc::new(Mutex::new(network_core::metadata::MetadataStore::new())),
            backend_manager,
            coordinator,
            load_balancer,
            network_state: Arc::new(Mutex::new(NetworkState::new())),
            gateway: Arc::new(Mutex::new(GatewayCapability::default())),
            statistics: Arc::new(EngineStatistics::new()),
            metrics: Arc::new(EngineMetrics::new()),
            packet_policy: Mutex::new(PacketActionPolicyConfig {
                default_action: network_core::PacketActionPolicy::Pass,
                rules: Vec::new(),
            }),
            processing_stop: Arc::new(AtomicBool::new(false)),
            processing_thread: Mutex::new(None),
            capture_stop: Arc::new(AtomicBool::new(false)),
            capture_thread: Mutex::new(None),
            windivert_action: Mutex::new(None),
            npcap_backend: Mutex::new(None),
            windivert_backend: Mutex::new(None),
            wfp_backend: Mutex::new(None),
            iphelper_backend: Mutex::new(None),
            etw_backend: Mutex::new(None),
            active_capture_backend: Mutex::new(None),
            active_reinjection_backend: Mutex::new(None),
            initialized: false,
        }
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized && self.state.is_initialized()
    }

    pub(crate) fn mark_initialized(&mut self) {
        self.initialized = true;
    }

    pub(crate) fn mark_uninitialized(&mut self) {
        self.initialized = false;
    }

    pub fn require_running(&self) -> EngineResult<()> {
        if !self.is_initialized() {
            return Err(network_core::EngineError::with_message(
                network_core::EngineErrorCode::NotInitialized,
                "engine is not initialized",
            ));
        }
        self.state.require_running()
    }

    pub(crate) fn set_active_capture_backend(
        &self,
        name: Option<String>,
    ) -> EngineResult<()> {
        let mut guard = self.active_capture_backend.lock().map_err(|_| {
            network_core::EngineError::with_message(
                network_core::EngineErrorCode::InternalError,
                "active capture backend mutex poisoned",
            )
        })?;
        *guard = name;
        Ok(())
    }

    pub(crate) fn set_active_reinjection_backend(
        &self,
        name: Option<String>,
    ) -> EngineResult<()> {
        let mut guard = self.active_reinjection_backend.lock().map_err(|_| {
            network_core::EngineError::with_message(
                network_core::EngineErrorCode::InternalError,
                "active reinjection backend mutex poisoned",
            )
        })?;
        *guard = name;
        Ok(())
    }

    pub fn active_capture_backend(&self) -> EngineResult<Option<String>> {
        self.active_capture_backend
            .lock()
            .map(|guard| guard.clone())
            .map_err(|_| {
                network_core::EngineError::with_message(
                    network_core::EngineErrorCode::InternalError,
                    "active capture backend mutex poisoned",
                )
            })
    }

    pub fn active_reinjection_backend(&self) -> EngineResult<Option<String>> {
        self.active_reinjection_backend
            .lock()
            .map(|guard| guard.clone())
            .map_err(|_| {
                network_core::EngineError::with_message(
                    network_core::EngineErrorCode::InternalError,
                    "active reinjection backend mutex poisoned",
                )
            })
    }

    pub fn set_packet_policy(&self, policy: PacketActionPolicyConfig) -> EngineResult<()> {
        self.require_running()?;
        let mut guard = self.packet_policy.lock().map_err(|_| {
            network_core::EngineError::with_message(
                network_core::EngineErrorCode::InternalError,
                "packet policy mutex poisoned",
            )
        })?;
        *guard = policy;
        Ok(())
    }

    pub fn packet_policy(&self) -> EngineResult<PacketActionPolicyConfig> {
        self.packet_policy
            .lock()
            .map(|guard| guard.clone())
            .map_err(|_| {
                network_core::EngineError::with_message(
                    network_core::EngineErrorCode::InternalError,
                    "packet policy mutex poisoned",
                )
            })
    }

    pub fn coordinator(&self) -> Arc<MultiBackendCoordinator> {
        Arc::clone(&self.coordinator)
    }

    pub fn load_balancer(&self) -> Arc<LoadBalancer> {
        Arc::clone(&self.load_balancer)
    }

    pub fn metrics(&self) -> MetricsView {
        MetricsView::new(Arc::clone(&self.metrics))
    }

    pub fn windivert_reinject(
        &self,
        data: &[u8],
        native_context: &[u8],
    ) -> EngineResult<()> {
        self.require_running()?;
        if data.is_empty() {
            return Err(network_core::EngineError::invalid_argument());
        }

        let backend_name = self
            .active_reinjection_backend()?
            .ok_or_else(|| {
                network_core::EngineError::with_message(
                    network_core::EngineErrorCode::CapabilityUnavailable,
                    "no active reinjection backend is selected",
                )
            })?;

        if !self
            .backend_manager
            .supports(&backend_name, backend_manager::BackendCapability::Reinjection)?
        {
            return Err(network_core::EngineError::with_message(
                network_core::EngineErrorCode::CapabilityUnavailable,
                format!("active reinjection backend '{}' does not provide reinjection", backend_name),
            ));
        }

        if backend_name != "windivert" {
            return Err(network_core::EngineError::with_message(
                network_core::EngineErrorCode::CapabilityUnavailable,
                format!(
                    "active reinjection backend '{}' has no Engine action executor",
                    backend_name
                ),
            ));
        }

        let mut guard = self.windivert_action.lock().map_err(|_| {
            network_core::EngineError::with_message(
                network_core::EngineErrorCode::InternalError,
                "WinDivert action mutex poisoned",
            )
        })?;

        if guard.is_none() {
            let mut config = WinDivertConfig::new("true", WinDivertLayer::Network)
                .map_err(|_| network_core::EngineError::backend_init_failed())?;
            config.send_only = true;
            let mut backend = WinDivertBackend::new(config);
            backend.start().map_err(|error| {
                network_core::EngineError::with_message(
                    network_core::EngineErrorCode::ReinjectionFailed,
                    format!("WinDivert action handle failed to open: {:?}", error),
                )
            })?;
            *guard = Some(backend);
        }

        guard
            .as_ref()
            .expect("WinDivert action backend initialized")
            .reinject_with_context(data, native_context)
            .map_err(|error| {
                let code = match error {
                    WinDivertError::InvalidOperation => {
                        network_core::EngineErrorCode::InvalidArgument
                    }
                    _ => network_core::EngineErrorCode::ReinjectionFailed,
                };
                network_core::EngineError::with_message(
                    code,
                    format!("WinDivert reinjection failed: {:?}", error),
                )
            })
    }
}

impl Default for EngineRuntime {
    fn default() -> Self {
        Self::new(4096, 1024, 65_536, 65_536)
    }
}

// ─────────────────────────────────────────────────────────────────────
// Global Engine singleton
// ─────────────────────────────────────────────────────────────────────

static GLOBAL_ENGINE: OnceLock<Mutex<Option<EngineRuntime>>> = OnceLock::new();

pub fn global_engine() -> &'static Mutex<Option<EngineRuntime>> {
    GLOBAL_ENGINE.get_or_init(|| Mutex::new(None))
}