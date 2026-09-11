use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

use crate::buffer::PacketBuffer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolError {
    InvalidConfiguration,
    Exhausted,
    InvalidBufferCapacity,
    PoolFull,
}

pub struct BufferPool {
    max_size: usize,
    buffer_capacity: usize,
    buffers: Mutex<Vec<PacketBuffer>>,
    allocated: AtomicUsize,
    in_use: AtomicUsize,
}

impl BufferPool {
    pub fn new(
        max_size: usize,
        buffer_capacity: usize,
    ) -> Result<Self, PoolError> {
        if max_size == 0 || buffer_capacity == 0 {
            return Err(PoolError::InvalidConfiguration);
        }

        Ok(Self {
            max_size,
            buffer_capacity,
            buffers: Mutex::new(Vec::with_capacity(max_size)),
            allocated: AtomicUsize::new(0),
            in_use: AtomicUsize::new(0),
        })
    }

    pub fn max_size(&self) -> usize {
        self.max_size
    }

    pub fn buffer_capacity(&self) -> usize {
        self.buffer_capacity
    }

    pub fn allocated(&self) -> usize {
        self.allocated.load(Ordering::Acquire)
    }

    pub fn in_use(&self) -> usize {
        self.in_use.load(Ordering::Acquire)
    }

    pub fn available(&self) -> usize {
        self.allocated().saturating_sub(self.in_use())
    }

    pub fn acquire(&self) -> Result<PacketBuffer, PoolError> {
        let mut buffers = self
            .buffers
            .lock()
            .map_err(|_| PoolError::Exhausted)?;

        if let Some(mut buffer) = buffers.pop() {
            drop(buffers);

            buffer
                .reset_for_reuse()
                .map_err(|_| PoolError::Exhausted)?;

            self.in_use.fetch_add(1, Ordering::AcqRel);

            return Ok(buffer);
        }

        drop(buffers);

        let mut current = self.allocated.load(Ordering::Acquire);

        loop {
            if current >= self.max_size {
                return Err(PoolError::Exhausted);
            }

            match self.allocated.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,

                Err(actual) => {
                    current = actual;
                }
            }
        }

        self.in_use.fetch_add(1, Ordering::AcqRel);

        Ok(PacketBuffer::new(self.buffer_capacity))
    }

    pub fn release(
        &self,
        mut buffer: PacketBuffer,
    ) -> Result<(), PoolError> {
        if buffer.capacity() != self.buffer_capacity {
            return Err(PoolError::InvalidBufferCapacity);
        }

        if !buffer.is_released() {
            buffer
                .release()
                .map_err(|_| PoolError::Exhausted)?;
        }

        let mut buffers = self
            .buffers
            .lock()
            .map_err(|_| PoolError::PoolFull)?;

        if buffers.len() >= self.max_size {
            drop(buffers);

            self.in_use.fetch_sub(1, Ordering::AcqRel);
            self.allocated.fetch_sub(1, Ordering::AcqRel);

            return Ok(());
        }

        buffers.push(buffer);

        drop(buffers);

        self.in_use.fetch_sub(1, Ordering::AcqRel);

        Ok(())
    }

    pub fn clear(&self) {
        if let Ok(mut buffers) = self.buffers.lock() {
            buffers.clear();
        }

        self.allocated
            .store(self.in_use(), Ordering::Release);
    }

    pub fn preallocate(&self, count: usize) -> usize {
        let target = count.min(self.max_size);
        let mut created = 0;

        let Ok(mut buffers) = self.buffers.lock() else {
            return 0;
        };

        while self.allocated.load(Ordering::Acquire) < target {
            let current = self.allocated.load(Ordering::Acquire);

            if current >= self.max_size {
                break;
            }

            if self
                .allocated
                .compare_exchange(
                    current,
                    current + 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                buffers.push(PacketBuffer::new(self.buffer_capacity));
                created += 1;
            }
        }

        created
    }
}

impl std::fmt::Debug for BufferPool {
    fn fmt(
        &self,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        formatter
            .debug_struct("BufferPool")
            .field("max_size", &self.max_size)
            .field("buffer_capacity", &self.buffer_capacity)
            .field("allocated", &self.allocated())
            .field("in_use", &self.in_use())
            .field("available", &self.available())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_configuration_is_rejected() {
        assert!(matches!(
            BufferPool::new(0, 1024),
            Err(PoolError::InvalidConfiguration)
        ));

        assert!(matches!(
            BufferPool::new(10, 0),
            Err(PoolError::InvalidConfiguration)
        ));
    }

    #[test]
    fn acquire_allocates_buffer() {
        let pool = BufferPool::new(4, 1024).unwrap();

        let buffer = pool.acquire().unwrap();

        assert_eq!(buffer.capacity(), 1024);
        assert_eq!(pool.allocated(), 1);
        assert_eq!(pool.in_use(), 1);
        assert_eq!(pool.available(), 0);
    }

    #[test]
    fn release_returns_buffer_to_pool() {
        let pool = BufferPool::new(4, 1024).unwrap();

        let buffer = pool.acquire().unwrap();

        pool.release(buffer).unwrap();

        assert_eq!(pool.allocated(), 1);
        assert_eq!(pool.in_use(), 0);
        assert_eq!(pool.available(), 1);
    }

    #[test]
    fn released_buffer_is_reused() {
        let pool = BufferPool::new(4, 1024).unwrap();

        let mut buffer = pool.acquire().unwrap();
        buffer.write(&[1, 2, 3]).unwrap();

        pool.release(buffer).unwrap();

        let buffer = pool.acquire().unwrap();

        assert!(buffer.is_empty());
        assert_eq!(buffer.capacity(), 1024);
        assert_eq!(pool.allocated(), 1);
        assert_eq!(pool.in_use(), 1);
    }

    #[test]
    fn pool_has_hard_allocation_limit() {
        let pool = BufferPool::new(2, 1024).unwrap();

        let first = pool.acquire().unwrap();
        let second = pool.acquire().unwrap();

        assert_eq!(
            pool.acquire().unwrap_err(),
            PoolError::Exhausted
        );

        pool.release(first).unwrap();
        pool.release(second).unwrap();
    }

    #[test]
    fn concurrent_acquisition_never_exceeds_limit() {
        use std::sync::Arc;
        use std::thread;

        let pool = Arc::new(BufferPool::new(8, 1024).unwrap());
        let mut threads = Vec::new();

        for _ in 0..32 {
            let pool = Arc::clone(&pool);

            threads.push(thread::spawn(move || {
                pool.acquire()
            }));
        }

        let mut acquired = Vec::new();

        for thread in threads {
            if let Ok(buffer) = thread.join().unwrap() {
                acquired.push(buffer);
            }
        }

        assert!(acquired.len() <= 8);
        assert!(pool.allocated() <= 8);

        for buffer in acquired {
            pool.release(buffer).unwrap();
        }
    }

    #[test]
    fn preallocate_creates_requested_buffers() {
        let pool = BufferPool::new(10, 512).unwrap();

        let created = pool.preallocate(5);

        assert_eq!(created, 5);
        assert_eq!(pool.allocated(), 5);
        assert_eq!(pool.available(), 5);
    }

    #[test]
    fn preallocate_is_bounded() {
        let pool = BufferPool::new(4, 512).unwrap();

        let created = pool.preallocate(100);

        assert_eq!(created, 4);
        assert_eq!(pool.allocated(), 4);
    }

    #[test]
    fn acquire_after_preallocation_does_not_allocate() {
        let pool = BufferPool::new(4, 512).unwrap();

        pool.preallocate(4);

        assert_eq!(pool.allocated(), 4);
        assert_eq!(pool.in_use(), 0);

        let _a = pool.acquire().unwrap();
        let _b = pool.acquire().unwrap();

        assert_eq!(pool.allocated(), 4);
        assert_eq!(pool.in_use(), 2);
        assert_eq!(pool.available(), 2);
    }

    #[test]
    fn wrong_capacity_is_rejected() {
        let pool = BufferPool::new(4, 1024).unwrap();
        let buffer = PacketBuffer::new(2048);

        assert_eq!(
            pool.release(buffer),
            Err(PoolError::InvalidBufferCapacity)
        );
    }

    #[test]
    fn clear_removes_idle_buffers() {
        let pool = BufferPool::new(4, 1024).unwrap();

        pool.preallocate(4);

        assert_eq!(pool.available(), 4);

        pool.clear();

        assert_eq!(pool.available(), 0);
    }

    #[test]
    fn release_marks_buffer_released() {
        let pool = BufferPool::new(4, 1024).unwrap();

        let buffer = pool.acquire().unwrap();

        pool.release(buffer).unwrap();

        assert_eq!(pool.available(), 1);
    }
}