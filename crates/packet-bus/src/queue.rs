use std::collections::VecDeque;
use std::sync::{Condvar, Mutex};

use network_core::observation::PacketObservation;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueError {
    Full,
    Closed,
}

struct QueueState {
    items: VecDeque<PacketObservation>,
    closed: bool,
}

pub struct ObservationQueue {
    capacity: usize,
    state: Mutex<QueueState>,
    available: Condvar,
    space: Condvar,
}

impl ObservationQueue {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            state: Mutex::new(QueueState {
                items: VecDeque::with_capacity(capacity),
                closed: false,
            }),
            available: Condvar::new(),
            space: Condvar::new(),
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn len(&self) -> usize {
        self.state
            .lock()
            .map(|state| state.items.len())
            .unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_full(&self) -> bool {
        self.capacity == 0 || self.len() >= self.capacity
    }

    pub fn is_closed(&self) -> bool {
        self.state
            .lock()
            .map(|state| state.closed)
            .unwrap_or(true)
    }

    pub fn try_enqueue(
        &self,
        observation: PacketObservation,
    ) -> Result<(), QueueError> {
        let mut state = self.state.lock().map_err(|_| QueueError::Closed)?;

        if state.closed {
            return Err(QueueError::Closed);
        }

        if self.capacity == 0 || state.items.len() >= self.capacity {
            return Err(QueueError::Full);
        }

        state.items.push_back(observation);
        self.available.notify_one();

        Ok(())
    }

    pub fn enqueue(
        &self,
        observation: PacketObservation,
    ) -> Result<(), QueueError> {
        let mut state = self.state.lock().map_err(|_| QueueError::Closed)?;

        loop {
            if state.closed {
                return Err(QueueError::Closed);
            }

            // A zero-capacity queue cannot ever accept an item. Returning
            // immediately avoids an uninterruptible wait with no possible
            // state transition that could make space available.
            if self.capacity == 0 {
                return Err(QueueError::Full);
            }

            if state.items.len() < self.capacity {
                state.items.push_back(observation);
                self.available.notify_one();
                return Ok(());
            }

            state = self
                .space
                .wait(state)
                .map_err(|_| QueueError::Closed)?;
        }
    }

    pub fn try_dequeue(
        &self,
    ) -> Result<Option<PacketObservation>, QueueError> {
        let mut state = self.state.lock().map_err(|_| QueueError::Closed)?;

        let item = state.items.pop_front();

        if item.is_some() {
            self.space.notify_one();
            return Ok(item);
        }

        if state.closed {
            return Ok(None);
        }

        Ok(None)
    }

    pub fn dequeue(&self) -> Result<PacketObservation, QueueError> {
        let mut state = self.state.lock().map_err(|_| QueueError::Closed)?;

        loop {
            if let Some(item) = state.items.pop_front() {
                self.space.notify_one();
                return Ok(item);
            }

            if state.closed {
                return Err(QueueError::Closed);
            }

            state = self
                .available
                .wait(state)
                .map_err(|_| QueueError::Closed)?;
        }
    }

    pub fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.closed = true;
            self.available.notify_all();
            self.space.notify_all();
        }
    }

    pub fn clear(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.items.clear();
            self.space.notify_all();
        }
    }
}

impl std::fmt::Debug for ObservationQueue {
    fn fmt(
        &self,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        formatter
            .debug_struct("ObservationQueue")
            .field("capacity", &self.capacity)
            .field("len", &self.len())
            .field("closed", &self.is_closed())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use network_core::{
        observation::{ObservationId, PacketObservation},
        packet::Packet,
        timestamp::Timestamp,
        BackendSource,
        Direction,
    };

    fn packet(id_data: u8) -> PacketObservation {
        let now = Timestamp::now();
        PacketObservation::new(
            ObservationId::new(id_data as u64),
            BackendSource::WinDivert,
            now,
            now,
            Direction::Inbound,
            "eth0",
            Packet::new(vec![id_data; 4]),
        )
    }

    #[test]
    fn creates_empty_queue() {
        let queue = ObservationQueue::new(4);

        assert_eq!(queue.capacity(), 4);
        assert_eq!(queue.len(), 0);
        assert!(queue.is_empty());
        assert!(!queue.is_full());
        assert!(!queue.is_closed());
    }

    #[test]
    fn enqueue_and_dequeue() {
        let queue = ObservationQueue::new(4);

        queue.try_enqueue(packet(1)).unwrap();

        assert_eq!(queue.len(), 1);

        let item = queue.try_dequeue().unwrap().unwrap();

        assert_eq!(item.packet.as_slice(), &[1, 1, 1, 1]);
        assert!(queue.is_empty());
    }

    #[test]
    fn fifo_order_is_preserved() {
        let queue = ObservationQueue::new(4);

        queue.try_enqueue(packet(1)).unwrap();
        queue.try_enqueue(packet(2)).unwrap();
        queue.try_enqueue(packet(3)).unwrap();

        assert_eq!(
            queue.try_dequeue().unwrap().unwrap().packet.as_slice(),
            &[1, 1, 1, 1]
        );
        assert_eq!(
            queue.try_dequeue().unwrap().unwrap().packet.as_slice(),
            &[2, 2, 2, 2]
        );
        assert_eq!(
            queue.try_dequeue().unwrap().unwrap().packet.as_slice(),
            &[3, 3, 3, 3]
        );
    }

    #[test]
    fn full_queue_rejects() {
        let queue = ObservationQueue::new(2);

        queue.try_enqueue(packet(1)).unwrap();
        queue.try_enqueue(packet(2)).unwrap();

        assert_eq!(queue.try_enqueue(packet(3)), Err(QueueError::Full));
        assert!(queue.is_full());
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn empty_queue_returns_none() {
        let queue = ObservationQueue::new(2);

        assert!(queue.try_dequeue().unwrap().is_none());
    }

    #[test]
    fn close_rejects_new_items() {
        let queue = ObservationQueue::new(2);

        queue.close();
        assert!(queue.is_closed());
        assert_eq!(queue.try_enqueue(packet(1)), Err(QueueError::Closed));
    }

    #[test]
    fn close_allows_draining_existing_items() {
        let queue = ObservationQueue::new(2);

        queue.try_enqueue(packet(1)).unwrap();
        queue.try_enqueue(packet(2)).unwrap();
        queue.close();

        assert_eq!(
            queue.try_dequeue().unwrap().unwrap().packet.as_slice(),
            &[1, 1, 1, 1]
        );
        assert_eq!(
            queue.try_dequeue().unwrap().unwrap().packet.as_slice(),
            &[2, 2, 2, 2]
        );
        assert!(queue.try_dequeue().unwrap().is_none());
    }

    #[test]
    fn clear_removes_items() {
        let queue = ObservationQueue::new(4);

        queue.try_enqueue(packet(1)).unwrap();
        queue.try_enqueue(packet(2)).unwrap();
        queue.clear();

        assert!(queue.is_empty());
    }

    #[test]
    fn zero_capacity_queue_rejects() {
        let queue = ObservationQueue::new(0);

        assert!(queue.is_full());
        assert_eq!(queue.try_enqueue(packet(1)), Err(QueueError::Full));
    }

    #[test]
    fn zero_capacity_blocking_enqueue_returns() {
        let queue = ObservationQueue::new(0);

        assert_eq!(queue.enqueue(packet(1)), Err(QueueError::Full));
    }

    #[test]
    fn concurrent_producers_are_bounded() {
        use std::sync::Arc;
        use std::thread;

        let queue = Arc::new(ObservationQueue::new(32));
        let mut workers = Vec::new();

        for i in 0..8 {
            let queue = Arc::clone(&queue);

            workers.push(thread::spawn(move || {
                for j in 0..100 {
                    let _ = queue.try_enqueue(packet((i + j) as u8));
                }
            }));
        }

        for worker in workers {
            worker.join().unwrap();
        }

        assert!(queue.len() <= queue.capacity());
    }

    #[test]
    fn blocking_enqueue_unblocks_after_dequeue() {
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let queue = Arc::new(ObservationQueue::new(1));
        queue.try_enqueue(packet(1)).unwrap();

        let producer_queue = Arc::clone(&queue);
        let producer = thread::spawn(move || {
            producer_queue.enqueue(packet(2)).unwrap();
        });

        thread::sleep(Duration::from_millis(20));
        assert_eq!(queue.len(), 1);

        queue.dequeue().unwrap();
        producer.join().unwrap();

        assert_eq!(queue.len(), 1);
        let item = queue.dequeue().unwrap();
        assert_eq!(item.packet.as_slice(), &[2, 2, 2, 2]);
    }

    #[test]
    fn blocking_dequeue_unblocks_on_close() {
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let queue = Arc::new(ObservationQueue::new(1));
        let consumer_queue = Arc::clone(&queue);

        let consumer = thread::spawn(move || consumer_queue.dequeue());

        thread::sleep(Duration::from_millis(20));
        queue.close();

        let result = consumer.join().unwrap();
        assert_eq!(result, Err(QueueError::Closed));
    }
}
