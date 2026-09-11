pub mod addresses;
pub mod dns;
pub mod gateways;
pub mod interfaces;
pub mod neighbors;
pub mod routes;
pub mod state;

pub use addresses::{
    AddressInfo,
    AddressScope,
    AddressState,
};

pub use dns::{
    DnsConfig,
    DnsServer,
};

pub use gateways::{
    GatewayInfo,
    GatewayType,
};

pub use interfaces::{
    InterfaceInfo,
    InterfaceKind,
    InterfaceState,
};

pub use neighbors::{
    NeighborInfo,
    NeighborState,
};

pub use routes::{
    RouteInfo,
    RouteProtocol,
    RouteType,
};

pub use state::{
    DnsConfiguration,
    NetworkState,
    NetworkStateSnapshot,
};