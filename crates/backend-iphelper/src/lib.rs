// crates/backend-iphelper/src/lib.rs

pub mod sockaddr;

pub mod connections;
pub mod interfaces;
pub mod neighbors;
pub mod routes;

pub use connections::{
    ConnectionInfo,
    ConnectionKey,
    ConnectionProtocol,
    ConnectionState,
    ConnectionTable,
    ConnectionTableError,
};

pub use interfaces::{
    InterfaceAddress,
    InterfaceInfo,
    InterfaceOperationalState,
    InterfaceTable,
    InterfaceQueryError,
    InterfaceType,
};

pub use neighbors::{
    NeighborInfo,
    NeighborKey,
    NeighborState,
    NeighborTable,
    NeighborTableError,
};

pub use routes::{
    RouteInfo,
    RouteProtocol,
    RouteTable,
    RouteTableError,
    RouteType,
};

use std::sync::{
    Arc,
    RwLock,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpHelperError {
    NotRunning,
    AlreadyRunning,
    InitializationFailed,
    QueryFailed,
}

#[derive(Debug)]
pub struct IpHelperBackend {
    running: bool,
    interfaces: Arc<RwLock<InterfaceTable>>,
    routes: Arc<RwLock<RouteTable>>,
    neighbors: Arc<RwLock<NeighborTable>>,
    connections: Arc<RwLock<ConnectionTable>>,
}

impl IpHelperBackend {
    pub fn new() -> Self {
        Self {
            running: false,
            interfaces: Arc::new(RwLock::new(InterfaceTable::new())),
            routes: Arc::new(RwLock::new(RouteTable::new())),
            neighbors: Arc::new(RwLock::new(NeighborTable::new())),
            connections: Arc::new(RwLock::new(ConnectionTable::new())),
        }
    }

    pub fn start(&mut self) -> Result<(), IpHelperError> {
        if self.running {
            return Err(IpHelperError::AlreadyRunning);
        }

        self.running = true;

        if let Err(error) = self.refresh_all() {
            self.running = false;
            return Err(error);
        }

        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), IpHelperError> {
        if !self.running {
            return Err(IpHelperError::NotRunning);
        }

        self.running = false;
        Ok(())
    }

    pub fn is_running(&self) -> bool {
        self.running
    }

    pub fn interfaces(&self) -> Arc<RwLock<InterfaceTable>> {
        Arc::clone(&self.interfaces)
    }

    pub fn routes(&self) -> Arc<RwLock<RouteTable>> {
        Arc::clone(&self.routes)
    }

    pub fn neighbors(&self) -> Arc<RwLock<NeighborTable>> {
        Arc::clone(&self.neighbors)
    }

    pub fn connections(&self) -> Arc<RwLock<ConnectionTable>> {
        Arc::clone(&self.connections)
    }

    pub fn interface_table(&self) -> Result<std::sync::RwLockReadGuard<'_, InterfaceTable>, IpHelperError> {
        self.interfaces.read().map_err(|_| IpHelperError::QueryFailed)
    }

    pub fn route_table(&self) -> Result<std::sync::RwLockReadGuard<'_, RouteTable>, IpHelperError> {
        self.routes.read().map_err(|_| IpHelperError::QueryFailed)
    }

    pub fn neighbor_table(&self) -> Result<std::sync::RwLockReadGuard<'_, NeighborTable>, IpHelperError> {
        self.neighbors.read().map_err(|_| IpHelperError::QueryFailed)
    }

    pub fn connection_table(&self) -> Result<std::sync::RwLockReadGuard<'_, ConnectionTable>, IpHelperError> {
        self.connections.read().map_err(|_| IpHelperError::QueryFailed)
    }

    pub fn clear_state(&self) -> Result<(), IpHelperError> {
        self.interfaces.write().map_err(|_| IpHelperError::QueryFailed)?.clear();
        self.routes.write().map_err(|_| IpHelperError::QueryFailed)?.clear();
        self.neighbors.write().map_err(|_| IpHelperError::QueryFailed)?.clear();
        self.connections.write().map_err(|_| IpHelperError::QueryFailed)?.clear();
        Ok(())
    }

    pub fn refresh_all(&self) -> Result<(), IpHelperError> {
        if !self.running {
            return Err(IpHelperError::NotRunning);
        }

        self.interfaces
            .write()
            .map_err(|_| IpHelperError::QueryFailed)?
            .refresh_all()
            .map_err(|_| IpHelperError::QueryFailed)?;

        self.routes
            .write()
            .map_err(|_| IpHelperError::QueryFailed)?
            .refresh_all()
            .map_err(|_| IpHelperError::QueryFailed)?;

        self.neighbors
            .write()
            .map_err(|_| IpHelperError::QueryFailed)?
            .refresh_all()
            .map_err(|_| IpHelperError::QueryFailed)?;

        self.connections
            .write()
            .map_err(|_| IpHelperError::QueryFailed)?
            .refresh_all()
            .map_err(|_| IpHelperError::QueryFailed)?;

        Ok(())
    }
}

impl Default for IpHelperBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for IpHelperBackend {
    fn drop(&mut self) {
        if self.running {
            self.running = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_starts() {
        let mut backend = IpHelperBackend::new();
        assert!(!backend.is_running());

        #[cfg(windows)]
        backend.start().unwrap();

        #[cfg(not(windows))]
        {
            backend.running = true;
            assert!(backend.is_running());
        }
    }

    #[test]
    fn backend_cannot_start_twice() {
        let mut backend = IpHelperBackend::new();

        #[cfg(windows)]
        backend.start().unwrap();
        #[cfg(not(windows))]
        {
            backend.running = true;
        }

        assert_eq!(backend.start(), Err(IpHelperError::AlreadyRunning));
    }

    #[test]
    fn backend_stops() {
        let mut backend = IpHelperBackend::new();

        #[cfg(windows)]
        backend.start().unwrap();
        #[cfg(not(windows))]
        {
            backend.running = true;
        }

        backend.stop().unwrap();
        assert!(!backend.is_running());
    }

    #[test]
    fn backend_cannot_stop_when_not_running() {
        let mut backend = IpHelperBackend::new();
        assert_eq!(backend.stop(), Err(IpHelperError::NotRunning));
    }

    #[test]
    fn backend_exposes_all_tables() {
        let backend = IpHelperBackend::new();
        assert!(backend.interface_table().is_ok());
        assert!(backend.route_table().is_ok());
        assert!(backend.neighbor_table().is_ok());
        assert!(backend.connection_table().is_ok());
    }

    #[test]
    fn backend_can_clear_state() {
        let backend = IpHelperBackend::new();
        backend.clear_state().unwrap();

        assert_eq!(backend.interface_table().unwrap().len(), 0);
        assert_eq!(backend.route_table().unwrap().len(), 0);
        assert_eq!(backend.neighbor_table().unwrap().len(), 0);
        assert_eq!(backend.connection_table().unwrap().len(), 0);
    }
}