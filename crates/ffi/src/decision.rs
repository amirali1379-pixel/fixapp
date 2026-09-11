use network_core::{Direction, PacketActionPolicy, PacketActionPolicyConfig, Protocol};
use packet_parser::{ParsedPacket, TransportProtocol};

/// Side-effect-free host policy decision. Backend execution happens separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketDecision {
    Pass,
    Drop,
    Inspect,
}

impl PacketDecision {
    pub const fn as_action_code(self) -> i32 {
        match self {
            Self::Pass => 0,
            Self::Drop => 1,
            Self::Inspect => 2,
        }
    }
}

pub fn evaluate_packet(
    parsed: &ParsedPacket,
    direction: Direction,
    policy: &PacketActionPolicyConfig,
) -> PacketDecision {
    let mut ordered: Vec<(u32, usize)> = policy
        .rules
        .iter()
        .enumerate()
        .map(|(index, rule)| (rule.priority, index))
        .collect();
    ordered.sort_unstable();

    for (_, index) in ordered {
        let rule = &policy.rules[index];
        if rule_matches(rule, parsed, direction) {
            return match rule.action {
                PacketActionPolicy::Pass => PacketDecision::Pass,
                PacketActionPolicy::Drop => PacketDecision::Drop,
                PacketActionPolicy::Inspect => PacketDecision::Inspect,
            };
        }
    }

    match policy.default_action {
        PacketActionPolicy::Pass => PacketDecision::Pass,
        PacketActionPolicy::Drop => PacketDecision::Drop,
        PacketActionPolicy::Inspect => PacketDecision::Inspect,
    }
}

fn rule_matches(
    rule: &network_core::FilterRule,
    parsed: &ParsedPacket,
    direction: Direction,
) -> bool {
    if let Some(expected) = rule.match_direction {
        if expected != direction {
            return false;
        }
    }

    if let Some(expected) = rule.match_protocol {
        let actual = match parsed.transport {
            TransportProtocol::Tcp => Protocol::Tcp,
            TransportProtocol::Udp => Protocol::Udp,
            TransportProtocol::Icmp => Protocol::Icmp,
            TransportProtocol::Icmpv6 => Protocol::IcmpV6,
            TransportProtocol::Unknown => return false,
        };
        if expected != actual {
            return false;
        }
    }

    if let Some(expected) = rule.match_src_ip {
        if parsed.source_ip != Some(expected) {
            return false;
        }
    }
    if let Some(expected) = rule.match_dst_ip {
        if parsed.destination_ip != Some(expected) {
            return false;
        }
    }
    if let Some(expected) = rule.match_src_port {
        if parsed.source_port != Some(expected) {
            return false;
        }
    }
    if let Some(expected) = rule.match_dst_port {
        if parsed.destination_port != Some(expected) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use network_core::FilterRule;
    use std::net::{IpAddr, Ipv4Addr};

    fn parsed_tcp() -> ParsedPacket {
        ParsedPacket {
            source: network_core::BackendSource::WinDivert,
            protocol: packet_parser::NetworkProtocol::Ipv4,
            transport: TransportProtocol::Tcp,
            payload_offset: 34,
            payload_length: 20,
            source_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            destination_ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            source_port: Some(50000),
            destination_port: Some(443),
        }
    }

    #[test]
    fn matching_rule_wins_over_default() {
        let policy = PacketActionPolicyConfig {
            default_action: PacketActionPolicy::Pass,
            rules: vec![FilterRule {
                priority: 10,
                match_direction: Some(Direction::Outbound),
                match_protocol: Some(Protocol::Tcp),
                match_src_ip: None,
                match_dst_ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
                match_src_port: None,
                match_dst_port: Some(443),
                action: PacketActionPolicy::Drop,
            }],
        };

        assert_eq!(
            evaluate_packet(&parsed_tcp(), Direction::Outbound, &policy),
            PacketDecision::Drop
        );
    }

    #[test]
    fn unmatched_rule_uses_default() {
        let policy = PacketActionPolicyConfig {
            default_action: PacketActionPolicy::Inspect,
            rules: Vec::new(),
        };

        assert_eq!(
            evaluate_packet(&parsed_tcp(), Direction::Outbound, &policy),
            PacketDecision::Inspect
        );
    }
}
