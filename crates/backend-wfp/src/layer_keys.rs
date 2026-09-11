//! Project-local mapping for WFP filtering layer identifiers.
//!
//! WFP layer keys are Windows-defined GUIDs. Keep this mapping isolated from
//! filter policy data so the policy model never has to manufacture GUIDs.

#[cfg(windows)]
pub(crate) type Guid = windows_sys::core::GUID;

/// Resolve the layer names accepted by the backend to their native WFP GUIDs.
/// Unknown names are rejected rather than converted to a zero/placeholder GUID.
#[cfg(windows)]
pub(crate) fn resolve(name: &str) -> Option<Guid> {
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;

    match name.trim().to_ascii_lowercase().as_str() {
        "ale_auth_connect_v4" | "ale-auth-connect-v4" => Some(FWPM_LAYER_ALE_AUTH_CONNECT_V4),
        "ale_auth_connect_v6" | "ale-auth-connect-v6" => Some(FWPM_LAYER_ALE_AUTH_CONNECT_V6),
        "ale_auth_recv_accept_v4" | "ale-auth-recv-accept-v4" => Some(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4),
        "ale_auth_recv_accept_v6" | "ale-auth-recv-accept-v6" => Some(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6),
        "datagram_data_v4" | "datagram-data-v4" => Some(FWPM_LAYER_DATAGRAM_DATA_V4),
        "datagram_data_v6" | "datagram-data-v6" => Some(FWPM_LAYER_DATAGRAM_DATA_V6),
        "inbound_transport_v4" | "inbound-transport-v4" => Some(FWPM_LAYER_INBOUND_TRANSPORT_V4),
        "inbound_transport_v6" | "inbound-transport-v6" => Some(FWPM_LAYER_INBOUND_TRANSPORT_V6),
        "outbound_transport_v4" | "outbound-transport-v4" => Some(FWPM_LAYER_OUTBOUND_TRANSPORT_V4),
        "outbound_transport_v6" | "outbound-transport-v6" => Some(FWPM_LAYER_OUTBOUND_TRANSPORT_V6),
        "inbound_ippacket_v4" | "inbound-ippacket-v4" => Some(FWPM_LAYER_INBOUND_IPPACKET_V4),
        "inbound_ippacket_v6" | "inbound-ippacket-v6" => Some(FWPM_LAYER_INBOUND_IPPACKET_V6),
        "outbound_ippacket_v4" | "outbound-ippacket-v4" => Some(FWPM_LAYER_OUTBOUND_IPPACKET_V4),
        "outbound_ippacket_v6" | "outbound-ippacket-v6" => Some(FWPM_LAYER_OUTBOUND_IPPACKET_V6),
        "ipforward_v4" | "ip-forward-v4" => Some(FWPM_LAYER_IPFORWARD_V4),
        "ipforward_v6" | "ip-forward-v6" => Some(FWPM_LAYER_IPFORWARD_V6),
        "stream_v4" | "stream-v4" => Some(FWPM_LAYER_STREAM_V4),
        "stream_v6" | "stream-v6" => Some(FWPM_LAYER_STREAM_V6),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    #[test]
    fn known_layers_resolve_without_placeholders() {
        assert!(super::resolve("ale_auth_connect_v4").is_some());
        assert!(super::resolve("outbound_transport_v4").is_some());
    }

    #[cfg(windows)]
    #[test]
    fn unknown_layer_is_rejected() {
        assert!(super::resolve("not-a-real-wfp-layer").is_none());
    }
}
