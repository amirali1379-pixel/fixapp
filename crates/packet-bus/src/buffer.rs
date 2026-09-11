use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug)]
pub struct PacketBuffer {
    data: Vec<u8>,
    length: usize,
    capacity: usize,
    released: AtomicBool,
}

impl PacketBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
            length: 0,
            capacity,
            released: AtomicBool::new(false),
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    pub fn is_full(&self) -> bool {
        self.length >= self.capacity
    }

    pub fn is_released(&self) -> bool {
        self.released.load(Ordering::Acquire)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.length]
    }

    pub fn clear(&mut self) {
        if self.is_released() {
            return;
        }

        self.data.clear();
        self.length = 0;
    }

    pub fn write(&mut self, bytes: &[u8]) -> Result<(), BufferError> {
        if self.is_released() {
            return Err(BufferError::Released);
        }

        if bytes.len() > self.capacity {
            return Err(BufferError::TooLarge {
                length: bytes.len(),
                capacity: self.capacity,
            });
        }

        self.data.clear();
        self.data.extend_from_slice(bytes);
        self.length = bytes.len();

        Ok(())
    }

    pub fn append(&mut self, bytes: &[u8]) -> Result<(), BufferError> {
        if self.is_released() {
            return Err(BufferError::Released);
        }

        let new_length = self
            .length
            .checked_add(bytes.len())
            .ok_or(BufferError::Overflow)?;

        if new_length > self.capacity {
            return Err(BufferError::TooLarge {
                length: new_length,
                capacity: self.capacity,
            });
        }

        self.data.extend_from_slice(bytes);
        self.length = new_length;

        Ok(())
    }

    pub fn release(&self) -> Result<(), BufferError> {
        if self
            .released
            .compare_exchange(
                false,
                true,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return Err(BufferError::AlreadyReleased);
        }

        Ok(())
    }

    pub fn reset_for_reuse(&mut self) -> Result<(), BufferError> {
        if !self.is_released() {
            return Err(BufferError::NotReleased);
        }

        self.data.clear();
        self.length = 0;

        self.released.store(false, Ordering::Release);

        Ok(())
    }

    pub fn into_vec(self) -> Result<Vec<u8>, BufferError> {
        if self.is_released() {
            return Err(BufferError::Released);
        }

        Ok(self.data)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufferError {
    Released,
    AlreadyReleased,
    NotReleased,
    TooLarge {
        length: usize,
        capacity: usize,
    },
    Overflow,
}

impl std::fmt::Display for BufferError {
    fn fmt(
        &self,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            Self::Released => {
                write!(formatter, "buffer has been released")
            }

            Self::AlreadyReleased => {
                write!(formatter, "buffer was already released")
            }

            Self::NotReleased => {
                write!(formatter, "buffer is not released")
            }

            Self::TooLarge { length, capacity } => {
                write!(
                    formatter,
                    "buffer size {} exceeds capacity {}",
                    length,
                    capacity
                )
            }

            Self::Overflow => {
                write!(formatter, "buffer length overflow")
            }
        }
    }
}

impl std::error::Error for BufferError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_empty_buffer() {
        let buffer = PacketBuffer::new(1024);

        assert_eq!(buffer.len(), 0);
        assert_eq!(buffer.capacity(), 1024);
        assert!(buffer.is_empty());
        assert!(!buffer.is_full());
        assert!(!buffer.is_released());
    }

    #[test]
    fn writes_packet() {
        let mut buffer = PacketBuffer::new(64);

        buffer.write(&[1, 2, 3, 4]).unwrap();

        assert_eq!(buffer.len(), 4);
        assert_eq!(buffer.as_slice(), &[1, 2, 3, 4]);
    }

    #[test]
    fn write_replaces_existing_data() {
        let mut buffer = PacketBuffer::new(64);

        buffer.write(&[1, 2, 3]).unwrap();
        buffer.write(&[9, 8]).unwrap();

        assert_eq!(buffer.len(), 2);
        assert_eq!(buffer.as_slice(), &[9, 8]);
    }

    #[test]
    fn append_works() {
        let mut buffer = PacketBuffer::new(64);

        buffer.write(&[1, 2]).unwrap();
        buffer.append(&[3, 4]).unwrap();

        assert_eq!(buffer.len(), 4);
        assert_eq!(buffer.as_slice(), &[1, 2, 3, 4]);
    }

    #[test]
    fn oversized_write_is_rejected() {
        let mut buffer = PacketBuffer::new(4);

        let result = buffer.write(&[1, 2, 3, 4, 5]);

        assert!(matches!(
            result,
            Err(BufferError::TooLarge {
                length: 5,
                capacity: 4
            })
        ));
    }

    #[test]
    fn oversized_append_is_rejected() {
        let mut buffer = PacketBuffer::new(4);

        buffer.write(&[1, 2, 3]).unwrap();

        let result = buffer.append(&[4, 5]);

        assert!(result.is_err());
        assert_eq!(buffer.len(), 3);
    }

    #[test]
    fn clear_works() {
        let mut buffer = PacketBuffer::new(64);

        buffer.write(&[1, 2, 3]).unwrap();
        buffer.clear();

        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);
    }

    #[test]
    fn release_is_one_way() {
        let mut buffer = PacketBuffer::new(64);

        buffer.write(&[1, 2, 3]).unwrap();

        buffer.release().unwrap();

        assert!(buffer.is_released());

        assert_eq!(
            buffer.release(),
            Err(BufferError::AlreadyReleased)
        );

        assert_eq!(
            buffer.write(&[4]),
            Err(BufferError::Released)
        );
    }

    #[test]
    fn released_buffer_can_be_reused() {
        let mut buffer = PacketBuffer::new(64);

        buffer.write(&[1, 2, 3]).unwrap();
        buffer.release().unwrap();

        buffer.reset_for_reuse().unwrap();

        assert!(!buffer.is_released());
        assert!(buffer.is_empty());

        buffer.write(&[9, 8]).unwrap();

        assert_eq!(buffer.as_slice(), &[9, 8]);
    }

    #[test]
    fn reuse_without_release_is_rejected() {
        let mut buffer = PacketBuffer::new(64);

        assert_eq!(
            buffer.reset_for_reuse(),
            Err(BufferError::NotReleased)
        );
    }

    #[test]
    fn zero_capacity_buffer_works() {
        let mut buffer = PacketBuffer::new(0);

        assert!(buffer.write(&[]).is_ok());
        assert!(buffer.write(&[1]).is_err());
    }
}