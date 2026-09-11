#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpPacket {
    pub type_: u8,
    pub code: u8,
    pub checksum: u16,
    pub rest: [u8; 4],
}

impl IcmpPacket {
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
        self.type_ == 8 && self.code == 0
    }

    pub fn is_echo_reply(&self) -> bool {
        self.type_ == 0 && self.code == 0
    }

    pub fn is_destination_unreachable(&self) -> bool {
        self.type_ == 3
    }

    pub fn is_time_exceeded(&self) -> bool {
        self.type_ == 11
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_echo_request() {
        let raw = [
            8, 0, 0, 0,
            0, 1, 0, 2,
        ];

        let packet = IcmpPacket::parse(&raw).unwrap();

        assert_eq!(packet.type_, 8);
        assert_eq!(packet.code, 0);
        assert!(packet.is_echo_request());
        assert!(!packet.is_echo_reply());
    }

    #[test]
    fn reject_short_packet() {
        assert!(IcmpPacket::parse(&[0; 7]).is_none());
    }
}