// dll/network-engine/src/backend_defaults.rs

use backend_contracts::all_known_descriptors;
use network_core::EngineResult;
use crate::engine::EngineRuntime;

/// Registers the built-in backend capability descriptors with the Engine.
///
/// The descriptor catalog lives in the `backend-contracts` crate, which is
/// the single source of truth for the Engine's intended capability layout
/// of known native backends.
///
/// Registration is metadata/orchestration only; it does not start native
/// backends.
pub(crate) fn register_builtin_backends(engine: &EngineRuntime) -> EngineResult<()> {
    for descriptor in all_known_descriptors() {
        if !engine.backend_manager.contains(&descriptor.name) {
            engine.backend_manager.register(descriptor)?;
        }
    }

    Ok(())
}