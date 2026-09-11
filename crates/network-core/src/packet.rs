/// Authoritative packet data container.
///
/// Packet owns the authoritative raw bytes. It does not automatically
/// mutate packet contents and is independent of any backend.
///
/// No WinDivert, Npcap, or WFP fields are present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    raw_bytes: Vec<u8>,
}

impl Packet {
    /// Creates a new packet from raw bytes.
    pub fn new(raw_bytes: Vec<u8>) -> Self {
        Self { raw_bytes }
    }

    /// Returns the length of the packet in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.raw_bytes.len()
    }

    /// Returns true if the packet contains no bytes.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.raw_bytes.is_empty()
    }

    /// Returns the allocated capacity of the internal buffer.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.raw_bytes.capacity()
    }

    /// Returns a read-only slice of the authoritative raw bytes.
    ///
    /// Packet contents must not be mutated implicitly by parsing,
    /// correlation, flow tracking, or backend-specific logic.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.raw_bytes
    }

    /// Consumes the packet and returns the underlying bytes.
    ///
    /// This is the explicit ownership-consuming operation for callers
    /// that need to transfer the raw buffer out of Packet.
    #[inline]
    pub fn into_vec(self) -> Vec<u8> {
        self.raw_bytes
    }

    /// Creates a packet only when raw data is non-empty.
    ///
    /// This is useful for capture backends because an empty capture
    /// must not become a PacketObservation.
    #[inline]
    pub fn try_new(raw_bytes: Vec<u8>) -> Option<Self> {
        if raw_bytes.is_empty() {
            None
        } else {
            Some(Self::new(raw_bytes))
        }
    }

    /// Returns the raw bytes together with their length without cloning.
    ///
    /// The returned slice remains read-only and the Packet retains
    /// authoritative ownership.
    #[inline]
    pub fn as_slice_with_len(&self) -> (&[u8], usize) {
        (&self.raw_bytes, self.raw_bytes.len())
    }
}

impl Default for Packet {
    fn default() -> Self {
        Self {
            raw_bytes: Vec::new(),
        }
    }
}

impl From<Vec<u8>> for Packet {
    fn from(raw_bytes: Vec<u8>) -> Self {
        Self::new(raw_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_owns_raw_bytes() {
        let data = vec![1, 2, 3, 4];
        let packet = Packet::new(data.clone());

        assert_eq!(packet.len(), 4);
        assert_eq!(packet.as_slice(), &[1, 2, 3, 4]);
        assert!(!packet.is_empty());
    }

    #[test]
    fn empty_packet() {
        let packet = Packet::default();

        assert_eq!(packet.len(), 0);
        assert!(packet.is_empty());
    }

    #[test]
    fn packet_capacity_matches_vec() {
        let data = Vec::with_capacity(1024);
        let packet = Packet::new(data);

        assert_eq!(packet.capacity(), 1024);
        assert_eq!(packet.len(), 0);
    }

    #[test]
    fn packet_does_not_auto_mutate() {
        let packet = Packet::new(vec![1, 2, 3]);

        assert_eq!(packet.as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn packet_from_vec() {
        let data = vec![5, 6, 7];
        let packet: Packet = data.into();

        assert_eq!(packet.len(), 3);
        assert_eq!(packet.as_slice(), &[5, 6, 7]);
    }

    #[test]
    fn packet_into_vec() {
        let packet = Packet::new(vec![8, 9]);
        let vec = packet.into_vec();

        assert_eq!(vec, &[8, 9]);
    }

    #[test]
    fn try_new_accepts_non_empty_packet() {
        let packet = Packet::try_new(vec![1, 2, 3]);

        assert!(packet.is_some());

        let packet = packet.unwrap();
        assert_eq!(packet.as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn try_new_rejects_empty_packet() {
        assert!(Packet::try_new(Vec::new()).is_none());
    }

    #[test]
    fn slice_with_len_matches_packet() {
        let packet = Packet::new(vec![10, 20, 30, 40]);

        let (bytes, len) = packet.as_slice_with_len();

        assert_eq!(bytes, &[10, 20, 30, 40]);
        assert_eq!(len, 4);
        assert_eq!(len, packet.len());
    }

    #[test]
    fn packet_preserves_authoritative_bytes() {
        let packet = Packet::new(vec![
            0x45, 0x00, 0x00, 0x28,
            0x12, 0x34, 0x00, 0x00,
        ]);

        assert_eq!(
            packet.as_slice(),
            &[
                0x45, 0x00, 0x00, 0x28,
                0x12, 0x34, 0x00, 0x00,
            ]
        );
    }
}