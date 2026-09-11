#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VlanHeader {
    pub tci: u16,
    pub ethertype: u16,
}

impl VlanHeader {
    pub const HEADER_LEN: usize = 4;

    pub fn parse(raw: &[u8]) -> Option<Self> {
        if raw.len() < Self::HEADER_LEN {
            return None;
        }

        Some(Self {
            tci: u16::from_be_bytes([raw[0], raw[1]]),
            ethertype: u16::from_be_bytes([raw[2], raw[3]]),
        })
    }

    pub fn priority(&self) -> u8 {
        ((self.tci >> 13) & 0x07) as u8
    }

    pub fn dei(&self) -> bool {
        (self.tci & 0x1000) != 0
    }

    pub fn vlan_id(&self) -> u16 {
        self.tci & 0x0fff
    }

    pub fn is_ipv4(&self) -> bool {
        self.ethertype == 0x0800
    }

    pub fn is_ipv6(&self) -> bool {
        self.ethertype == 0x86dd
    }

    pub fn is_arp(&self) -> bool {
        self.ethertype == 0x0806
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_vlan() {
        let raw = [
            0x60, 0x64,
            0x08, 0x00,
        ];

        let vlan = VlanHeader::parse(&raw).unwrap();

        assert_eq!(vlan.vlan_id(), 100);
        assert_eq!(vlan.priority(), 3);
        assert!(!vlan.dei());
        assert!(vlan.is_ipv4());
    }

    #[test]
    fn reject_short_header() {
        assert!(VlanHeader::parse(&[0; 3]).is_none());
    }
}