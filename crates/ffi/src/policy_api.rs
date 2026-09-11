// crates/ffi/src/policy_api.rs
//
// Host packet action policy configuration entry points.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::raw::c_int;

use network_core::{
    Direction,
    FilterRule,
    PacketActionPolicy,
    PacketActionPolicyConfig,
    Protocol,
};

use crate::{
    engine::global_engine,
    errors::*,
    validation::validate_not_null,
};

fn action(v: c_int) -> Option<PacketActionPolicy> {
    match v {
        0 => Some(PacketActionPolicy::Pass),
        1 => Some(PacketActionPolicy::Drop),
        2 => Some(PacketActionPolicy::Inspect),
        _ => None,
    }
}

fn direction(v: c_int) -> Option<Option<Direction>> {
    match v {
        -1 => Some(None),
        0 => Some(Some(Direction::Inbound)),
        1 => Some(Some(Direction::Outbound)),
        2 => Some(Some(Direction::Unknown)),
        _ => None,
    }
}

fn protocol(v: c_int) -> Option<Option<Protocol>> {
    match v {
        -1 => Some(None),
        1 => Some(Some(Protocol::Icmp)),
        6 => Some(Some(Protocol::Tcp)),
        17 => Some(Some(Protocol::Udp)),
        58 => Some(Some(Protocol::IcmpV6)),
        0..=255 => Some(Some(Protocol::Other(v as u8))),
        _ => None,
    }
}

fn ip(family: c_int, bytes: *const u8) -> Option<Option<IpAddr>> {
    if family == 0 {
        return Some(None);
    }
    if validate_not_null(bytes) != NE_OK {
        return None;
    }
    let len = match family {
        4 => 4,
        6 => 16,
        _ => return None,
    };
    let bytes = unsafe { std::slice::from_raw_parts(bytes, len) };
    match family {
        4 => Some(Some(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        )))),
        6 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(bytes);
            Some(Some(IpAddr::V6(Ipv6Addr::from(octets))))
        }
        _ => None,
    }
}

#[no_mangle]
pub extern "C" fn packet_policy_set_default(action_value: c_int) -> c_int {
    let action = match action(action_value) {
        Some(v) => v,
        None => return NE_ERROR_INVALID_ARGUMENT,
    };

    let g = match global_engine().lock() {
        Ok(v) => v,
        Err(_) => return NE_ERROR_INTERNAL,
    };
    let Some(engine) = g.as_ref() else {
        return NE_ERROR_NOT_INITIALIZED;
    };

    let rules = match engine.packet_policy() {
        Ok(current) => current.rules,
        Err(_) => return NE_ERROR_INTERNAL,
    };

    let new_policy = PacketActionPolicyConfig {
        default_action: action,
        rules,
    };

    match engine.set_packet_policy(new_policy) {
        Ok(()) => NE_OK,
        Err(_) => NE_ERROR_INTERNAL,
    }
}

#[no_mangle]
pub extern "C" fn packet_policy_clear_rules() -> c_int {
    let g = match global_engine().lock() {
        Ok(v) => v,
        Err(_) => return NE_ERROR_INTERNAL,
    };
    let Some(engine) = g.as_ref() else {
        return NE_ERROR_NOT_INITIALIZED;
    };

    let default_action = match engine.packet_policy() {
        Ok(current) => current.default_action,
        Err(_) => return NE_ERROR_INTERNAL,
    };

    let new_policy = PacketActionPolicyConfig {
        default_action,
        rules: Vec::new(),
    };

    match engine.set_packet_policy(new_policy) {
        Ok(()) => NE_OK,
        Err(_) => NE_ERROR_INTERNAL,
    }
}

#[no_mangle]
pub extern "C" fn packet_policy_add_rule(
    priority: u32,
    direction_value: c_int,
    protocol_value: c_int,
    src_ip_family: c_int,
    src_ip: *const u8,
    dst_ip_family: c_int,
    dst_ip: *const u8,
    src_port: u16,
    dst_port: u16,
    action_value: c_int,
) -> c_int {
    let action = match action(action_value) {
        Some(v) => v,
        None => return NE_ERROR_INVALID_ARGUMENT,
    };
    let direction = match direction(direction_value) {
        Some(v) => v,
        None => return NE_ERROR_INVALID_ARGUMENT,
    };
    let protocol = match protocol(protocol_value) {
        Some(v) => v,
        None => return NE_ERROR_INVALID_ARGUMENT,
    };
    let src_ip = match ip(src_ip_family, src_ip) {
        Some(v) => v,
        None => return NE_ERROR_INVALID_ARGUMENT,
    };
    let dst_ip = match ip(dst_ip_family, dst_ip) {
        Some(v) => v,
        None => return NE_ERROR_INVALID_ARGUMENT,
    };

    let rule = FilterRule {
        priority,
        match_direction: direction,
        match_protocol: protocol,
        match_src_ip: src_ip,
        match_dst_ip: dst_ip,
        match_src_port: (src_port != 0).then_some(src_port),
        match_dst_port: (dst_port != 0).then_some(dst_port),
        action,
    };

    let g = match global_engine().lock() {
        Ok(v) => v,
        Err(_) => return NE_ERROR_INTERNAL,
    };
    let Some(engine) = g.as_ref() else {
        return NE_ERROR_NOT_INITIALIZED;
    };

    let mut current = match engine.packet_policy() {
        Ok(c) => c,
        Err(_) => return NE_ERROR_INTERNAL,
    };
    current.rules.push(rule);

    match engine.set_packet_policy(current) {
        Ok(()) => NE_OK,
        Err(_) => NE_ERROR_INTERNAL,
    }
}