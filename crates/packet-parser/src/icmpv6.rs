#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpV6Packet {
    pub type_: u8,
    pub code: u8,
    pub checksum: u16,
    pub rest: [u8; 4],
}

impl IcmpV6Packet {
    pub const HEADER_LEN: usize = 8;

    pub fn parse(raw: &[u8]) -> Option<Self> {
        if raw.len() < Self::HEADER_LEN {
            return None;
        }

        let type_ = raw[0];
        let code = raw[1];
        let checksum = u16::from_be_bytes([raw[2], raw[3]]);

        let mut rest = [0u8; 4];
        rest.copy_from_slice(&raw[4..8]);

        Some(Self {
            type_,
            code,
            checksum,
            rest,
        })
    }

    pub fn is_echo_request(&self) -> bool {
        self.type_ == 128 && self.code == 0
    }

    pub fn is_echo_reply(&self) -> bool {
        self.type_ == 129 && self.code == 0
    }

    pub fn is_neighbor_solicitation(&self) -> bool {
        self.type_ == 135
    }

    pub fn is_neighbor_advertisement(&self) -> bool {
        self.type_ == 136
    }

    pub fn is_router_solicitation(&self) -> bool {
        self.type_ == 133
    }

    pub fn is_router_advertisement(&self) -> bool {
        self.type_ == 134
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_echo_request() {
        let raw = [
            128, 0, 0, 0,
            0, 1, 0, 2,
        ];

        let packet = IcmpV6Packet::parse(&raw).unwrap();

        assert_eq!(packet.type_, 128);
        assert!(packet.is_echo_request());
    }

    #[test]
    fn reject_short_packet() {
        assert!(IcmpV6Packet::parse(&[0; 7]).is_none());
    }
}