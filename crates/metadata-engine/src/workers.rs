// crates/metadata-engine/src/workers.rs

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use network_core::observation::ObservationId;

const DEFAULT_QUEUE_CAPACITY: usize = 256;
const RECEIVE_POLL_INTERVAL: Duration = Duration::from_millis(100);
const SHUTDOWN_DRAIN_INTERVAL: Duration = Duration::from_millis(1);

#[derive(Debug)]
pub enum WorkItem {
    ReverseDnsLookup {
        observation_id: ObservationId,
        address: std::net::IpAddr,
    },
}

#[derive(Debug)]
pub enum WorkResult {
    ReverseDnsLookup {
        observation_id: ObservationId,
        address: std::net::IpAddr,
        hostname: Option<String>,
    },
}

#[derive(Debug)]
pub struct MetadataWorker {
    pub id: usize,
    pub active: AtomicBool,
}

impl MetadataWorker {
    pub fn new(id: usize) -> Self {
        Self {
            id,
            active: AtomicBool::new(false),
        }
    }

    pub fn start(&self) {
        self.active.store(true, Ordering::Release);
    }

    pub fn stop(&self) {
        self.active.store(false, Ordering::Release);
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
pub struct WorkerPool {
    workers: Vec<Arc<MetadataWorker>>,
    senders: Vec<mpsc::SyncSender<WorkItem>>,
    next_worker: AtomicUsize,
    result_receiver: Mutex<mpsc::Receiver<WorkResult>>,
    handles: Vec<JoinHandle<()>>,
}

impl WorkerPool {
    pub fn new(count: usize) -> Self {
        Self::with_queue_capacity(count, DEFAULT_QUEUE_CAPACITY)
    }

    pub fn with_queue_capacity(count: usize, queue_capacity: usize) -> Self {
        let worker_count = count.max(1);
        let capacity = queue_capacity.max(1);
        let (result_sender, result_receiver) =
            mpsc::sync_channel::<WorkResult>(capacity * worker_count);

        let mut handles = Vec::with_capacity(worker_count);
        let mut workers = Vec::with_capacity(worker_count);
        let mut senders = Vec::with_capacity(worker_count);

        // Give every worker its own bounded queue. A shared Mutex<Receiver>
        // would serialize receive operations and defeat the worker pool.
        for id in 0..worker_count {
            let (sender, receiver) = mpsc::sync_channel::<WorkItem>(capacity);
            let worker = Arc::new(MetadataWorker::new(id));
            worker.start();
            let worker_thread = Arc::clone(&worker);
            let worker_result_sender = result_sender.clone();

            let handle = thread::spawn(move || {
                loop {
                    // Stopping admission does not abandon already queued work.
                    // The queue is allowed to drain until all senders are gone.
                    match receiver.recv_timeout(RECEIVE_POLL_INTERVAL) {
                        Ok(item) => {
                            if let Some(result) = Self::process_item(item, worker_thread.id) {
                                // Result delivery is part of the work contract. Apply
                                // bounded backpressure instead of silently discarding a
                                // completed DNS result when the result queue is full.
                                if worker_result_sender.send(result).is_err() {
                                    break;
                                }
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            if !worker_thread.is_active() {
                                continue;
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
            });

            senders.push(sender);
            handles.push(handle);
            workers.push(worker);
        }

        drop(result_sender);

        Self {
            workers,
            senders,
            next_worker: AtomicUsize::new(0),
            result_receiver: Mutex::new(result_receiver),
            handles,
        }
    }

    pub fn start_all(&self) {
        for worker in &self.workers {
            worker.start();
        }
    }

    pub fn stop_all(&mut self) {
        for worker in &self.workers {
            worker.stop();
        }

        // Closing admission disconnects worker input only after all queued work
        // has been consumed. Workers therefore drain accepted work instead of
        // abandoning it during shutdown.
        self.senders.clear();

        // Workers can block on the bounded result channel while publishing a
        // completed item. Drain results while they finish so shutdown cannot
        // strand completed metadata behind a full result queue.
        loop {
            let any_running = self.handles.iter().any(|handle| !handle.is_finished());
            if !any_running {
                break;
            }

            self.drain_results();
            thread::sleep(SHUTDOWN_DRAIN_INTERVAL);
        }

        for handle in self.handles.drain(..) {
            let _ = handle.join();
        }

        self.drain_results();
    }

    pub fn enqueue(&self, item: WorkItem) -> Result<(), mpsc::TrySendError<WorkItem>> {
        if self.senders.is_empty() {
            return Err(mpsc::TrySendError::Disconnected(item));
        }

        // Round-robin first, then probe the remaining bounded queues. This
        // keeps normal distribution balanced while making queue saturation
        // observable instead of silently dropping work.
        let start = self.next_worker.fetch_add(1, Ordering::Relaxed) % self.senders.len();
        let mut item = item;
        let mut saw_full = false;

        for offset in 0..self.senders.len() {
            let index = (start + offset) % self.senders.len();
            match self.senders[index].try_send(item) {
                Ok(()) => return Ok(()),
                Err(mpsc::TrySendError::Full(returned)) => {
                    item = returned;
                    saw_full = true;
                }
                Err(mpsc::TrySendError::Disconnected(returned)) => {
                    item = returned;
                }
            }
        }

        if saw_full {
            Err(mpsc::TrySendError::Full(item))
        } else {
            Err(mpsc::TrySendError::Disconnected(item))
        }
    }

    pub fn try_recv_result(&self) -> Result<Option<WorkResult>, mpsc::TryRecvError> {
        let receiver = self
            .result_receiver
            .lock()
            .map_err(|_| mpsc::TryRecvError::Disconnected)?;
        match receiver.try_recv() {
            Ok(result) => Ok(Some(result)),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => Err(mpsc::TryRecvError::Disconnected),
        }
    }

    pub fn active_count(&self) -> usize {
        self.workers
            .iter()
            .filter(|worker| worker.is_active())
            .count()
    }

    pub fn len(&self) -> usize {
        self.workers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.workers.is_empty()
    }

    fn drain_results(&self) {
        if let Ok(receiver) = self.result_receiver.lock() {
            while receiver.try_recv().is_ok() {}
        }
    }

    /// Processes a single work item.
    ///
    /// Per the updated architecture (see CORE_MODEL.txt / PROJECT_NATURE.txt),
    /// DNS enrichment must be derived from packet payloads, not from the
    /// Windows DNS client. Until packet-payload DNS extraction is available,
    /// this worker returns `hostname = None` and leaves the resolution step
    /// to a future packet-payload DNS extractor.
    fn process_item(item: WorkItem, _worker_id: usize) -> Option<WorkResult> {
        match item {
            WorkItem::ReverseDnsLookup {
                observation_id,
                address,
            } => Some(WorkResult::ReverseDnsLookup {
                observation_id,
                address,
                hostname: None,
            }),
        }
    }
}

impl Drop for WorkerPool {
    fn drop(&mut self) {
        self.stop_all();
    }
}