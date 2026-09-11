#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::time::{Duration, Instant};

use network_core::error::EngineError;

use crate::flow::{Flow, FlowDirection};
use crate::key::FlowKey;
use crate::state::FlowState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowTableStats {
    pub current_entries: usize,
    pub max_entries: usize,
    pub total_created: u64,
    pub total_removed: u64,
    pub total_expired: u64,
}

#[derive(Debug)]
pub struct FlowTable {
    flows: HashMap<FlowKey, Flow>,
    max_entries: usize,
    idle_timeout: Duration,
    total_created: u64,
    total_removed: u64,
    total_expired: u64,
}

impl FlowTable {
    pub fn new(
        max_entries: usize,
        idle_timeout: Duration,
    ) -> Result<Self, EngineError> {
        if max_entries == 0 {
            return Err(EngineError::invalid_argument());
        }

        if idle_timeout.is_zero() {
            return Err(EngineError::invalid_argument());
        }

        Ok(Self {
            flows: HashMap::with_capacity(
                max_entries.min(1024),
            ),
            max_entries,
            idle_timeout,
            total_created: 0,
            total_removed: 0,
            total_expired: 0,
        })
    }

    pub fn with_defaults(
        max_entries: usize,
    ) -> Result<Self, EngineError> {
        Self::new(
            max_entries,
            Duration::from_secs(300),
        )
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    pub fn contains(
        &self,
        key: &FlowKey,
    ) -> bool {
        self.flows.contains_key(key)
            || self.flows.contains_key(&key.reverse())
    }

    pub fn get(
        &self,
        key: &FlowKey,
    ) -> Option<&Flow> {
        self.flows
            .get(key)
            .or_else(|| self.flows.get(&key.reverse()))
    }

    pub fn get_mut(
        &mut self,
        key: &FlowKey,
    ) -> Option<&mut Flow> {
        if self.flows.contains_key(key) {
            return self.flows.get_mut(key);
        }

        let reverse = key.reverse();

        self.flows.get_mut(&reverse)
    }

    pub fn insert(
        &mut self,
        flow: Flow,
    ) -> Result<bool, EngineError> {
        if self.flows.contains_key(&flow.key)
            || self.flows.contains_key(&flow.key.reverse())
        {
            return Ok(false);
        }

        if self.flows.len() >= self.max_entries {
            return Err(
                EngineError::resource_exhausted()
            );
        }

        self.flows.insert(
            flow.key.clone(),
            flow,
        );

        self.total_created =
            self.total_created.saturating_add(1);

        Ok(true)
    }

    pub fn get_or_create(
        &mut self,
        key: FlowKey,
    ) -> Result<&mut Flow, EngineError> {
        if self.flows.contains_key(&key) {
            return Ok(self
                .flows
                .get_mut(&key)
                .expect("flow exists after contains_key"));
        }

        let reverse = key.reverse();

        if self.flows.contains_key(&reverse) {
            return Ok(self
                .flows
                .get_mut(&reverse)
                .expect("reverse flow exists after contains_key"));
        }

        if self.flows.len() >= self.max_entries {
            return Err(
                EngineError::resource_exhausted()
            );
        }

        self.flows.insert(
            key.clone(),
            Flow::new(key.clone()),
        );

        self.total_created =
            self.total_created.saturating_add(1);

        Ok(self
            .flows
            .get_mut(&key)
            .expect("flow inserted successfully"))
    }

    pub fn record_packet(
        &mut self,
        key: FlowKey,
        bytes: usize,
        direction: FlowDirection,
        timestamp_ns: Option<u64>,
    ) -> Result<(), EngineError> {
        let flow = self.get_or_create(key)?;

        flow.record_packet(
            bytes,
            direction,
            timestamp_ns,
        );

        Ok(())
    }

    pub fn update(
        &mut self,
        key: &FlowKey,
        bytes: usize,
        direction: FlowDirection,
        timestamp_ns: Option<u64>,
    ) -> Result<bool, EngineError> {
        match self.get_mut(key) {
            Some(flow) => {
                flow.record_packet(
                    bytes,
                    direction,
                    timestamp_ns,
                );

                Ok(true)
            }

            None => Ok(false),
        }
    }

    pub fn remove(
        &mut self,
        key: &FlowKey,
    ) -> Option<Flow> {
        let removed = if self.flows.contains_key(key) {
            self.flows.remove(key)
        } else {
            let reverse = key.reverse();
            self.flows.remove(&reverse)
        };

        if removed.is_some() {
            self.total_removed =
                self.total_removed.saturating_add(1);
        }

        removed
    }

    pub fn close(
        &mut self,
        key: &FlowKey,
    ) -> bool {
        match self.get_mut(key) {
            Some(flow) => {
                flow.close();
                true
            }
            None => false,
        }
    }

    pub fn expire_idle(
        &mut self,
        now_ns: u64,
    ) -> usize {
        let timeout = self.idle_timeout;

        let expired_keys: Vec<FlowKey> = self
            .flows
            .iter()
            .filter_map(|(key, flow)| {
                if flow.is_idle(
                    now_ns,
                    timeout,
                ) {
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect();

        let count = expired_keys.len();

        for key in expired_keys {
            if let Some(mut flow) =
                self.flows.remove(&key)
            {
                flow.mark_expired();

                self.total_removed =
                    self.total_removed.saturating_add(1);

                self.total_expired =
                    self.total_expired.saturating_add(1);
            }
        }

        count
    }

    pub fn expire_idle_now(&mut self) -> usize {
        self.expire_idle(now_ns())
    }

    pub fn clear(&mut self) -> usize {
        let count = self.flows.len();

        self.flows.clear();

        self.total_removed = self
            .total_removed
            .saturating_add(count as u64);

        count
    }

    pub fn keys(&self) -> Vec<FlowKey> {
        self.flows.keys().cloned().collect()
    }

    pub fn values(&self) -> impl Iterator<Item = &Flow> {
        self.flows.values()
    }

    pub fn stats(&self) -> FlowTableStats {
        FlowTableStats {
            current_entries: self.flows.len(),
            max_entries: self.max_entries,
            total_created: self.total_created,
            total_removed: self.total_removed,
            total_expired: self.total_expired,
        }
    }

    pub fn capacity_available(&self) -> usize {
        self.max_entries
            .saturating_sub(self.flows.len())
    }
}

fn now_ns() -> u64 {
    static BASELINE: std::sync::OnceLock<Instant> =
        std::sync::OnceLock::new();

    let baseline = BASELINE.get_or_init(Instant::now);
    baseline
        .elapsed()
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64
}

impl Default for FlowTable {
    fn default() -> Self {
        Self {
            flows: HashMap::new(),
            max_entries: 100_000,
            idle_timeout: Duration::from_secs(300),
            total_created: 0,
            total_removed: 0,
            total_expired: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(
        source_port: u16,
        destination_port: u16,
    ) -> FlowKey {
        FlowKey::new(
            "192.168.1.10".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            source_port,
            destination_port,
            6,
        )
    }

    #[test]
    fn creates_table() {
        let table = FlowTable::new(
            100,
            Duration::from_secs(30),
        )
        .unwrap();

        assert_eq!(table.len(), 0);
        assert_eq!(table.max_entries(), 100);
    }

    #[test]
    fn rejects_zero_capacity() {
        assert!(
            FlowTable::new(
                0,
                Duration::from_secs(30)
            ).is_err()
        );
    }

    #[test]
    fn inserts_flow() {
        let mut table = FlowTable::new(
            10,
            Duration::from_secs(30),
        )
        .unwrap();

        let flow = Flow::new(key(1000, 443));

        assert!(
            table.insert(flow).unwrap()
        );

        assert_eq!(table.len(), 1);
    }

    #[test]
    fn duplicate_insert_does_not_replace() {
        let mut table = FlowTable::new(
            10,
            Duration::from_secs(30),
        )
        .unwrap();

        let first = Flow::new(key(1000, 443));

        assert!(
            table.insert(first).unwrap()
        );

        assert!(
            !table
                .insert(Flow::new(key(1000, 443)))
                .unwrap()
        );

        assert_eq!(table.len(), 1);
    }

    #[test]
    fn capacity_is_enforced() {
        let mut table = FlowTable::new(
            1,
            Duration::from_secs(30),
        )
        .unwrap();

        table
            .insert(Flow::new(key(1000, 443)))
            .unwrap();

        let result =
            table.insert(
                Flow::new(key(1001, 443))
            );

        assert_eq!(
            result.unwrap_err(),
            EngineError::resource_exhausted()
        );
    }

    #[test]
    fn get_or_create_reuses_existing_flow() {
        let mut table = FlowTable::new(
            10,
            Duration::from_secs(30),
        )
        .unwrap();

        table
            .record_packet(
                key(1000, 443),
                100,
                FlowDirection::Forward,
                Some(100),
            )
            .unwrap();

        table
            .record_packet(
                key(1000, 443),
                200,
                FlowDirection::Forward,
                Some(200),
            )
            .unwrap();

        assert_eq!(table.len(), 1);

        let flow =
            table.get(&key(1000, 443)).unwrap();

        assert_eq!(flow.packets, 2);
        assert_eq!(flow.bytes, 300);
    }

    #[test]
    fn reverse_key_finds_same_flow() {
        let mut table = FlowTable::new(
            10,
            Duration::from_secs(30),
        )
        .unwrap();

        let original = key(1000, 443);
        let reverse = original.reverse();

        table
            .insert(Flow::new(original.clone()))
            .unwrap();

        assert!(table.contains(&reverse));
        assert!(table.get(&reverse).is_some());
    }

    #[test]
    fn reverse_record_reuses_existing_flow() {
        let mut table = FlowTable::new(
            10,
            Duration::from_secs(30),
        )
        .unwrap();

        let original = key(1000, 443);
        let reverse = original.reverse();

        table
            .record_packet(
                original,
                100,
                FlowDirection::Forward,
                Some(100),
            )
            .unwrap();

        table
            .record_packet(
                reverse,
                200,
                FlowDirection::Reverse,
                Some(200),
            )
            .unwrap();

        assert_eq!(table.len(), 1);
        assert_eq!(table.stats().total_created, 1);
        assert_eq!(table.get(&key(1000, 443)).unwrap().packets, 2);
        assert_eq!(table.get(&key(1000, 443)).unwrap().bytes, 300);
    }

    #[test]
    fn update_existing_flow() {
        let mut table = FlowTable::new(
            10,
            Duration::from_secs(30),
        )
        .unwrap();

        let flow_key = key(1000, 443);

        table
            .insert(Flow::new(flow_key.clone()))
            .unwrap();

        assert!(
            table.update(
                &flow_key,
                1500,
                FlowDirection::Forward,
                Some(1000),
            ).unwrap()
        );

        assert_eq!(
            table.get(&flow_key)
                .unwrap()
                .bytes,
            1500
        );
    }

    #[test]
    fn update_missing_flow_returns_false() {
        let mut table = FlowTable::new(
            10,
            Duration::from_secs(30),
        )
        .unwrap();

        assert!(
            !table.update(
                &key(1000, 443),
                100,
                FlowDirection::Forward,
                Some(100),
            ).unwrap()
        );
    }

    #[test]
    fn removes_flow() {
        let mut table = FlowTable::new(
            10,
            Duration::from_secs(30),
        )
        .unwrap();

        let flow_key = key(1000, 443);

        table
            .insert(Flow::new(flow_key.clone()))
            .unwrap();

        assert!(
            table.remove(&flow_key).is_some()
        );

        assert_eq!(table.len(), 0);
    }

    #[test]
    fn removes_flow_by_reverse_key() {
        let mut table = FlowTable::new(
            10,
            Duration::from_secs(30),
        )
        .unwrap();

        let flow_key = key(1000, 443);
        let reverse = flow_key.reverse();

        table
            .insert(Flow::new(flow_key))
            .unwrap();

        assert!(table.remove(&reverse).is_some());
        assert!(table.is_empty());
    }

    #[test]
    fn closes_flow() {
        let mut table = FlowTable::new(
            10,
            Duration::from_secs(30),
        )
        .unwrap();

        let flow_key = key(1000, 443);

        table
            .insert(Flow::new(flow_key.clone()))
            .unwrap();

        assert!(table.close(&flow_key));

        assert!(
            table
                .get(&flow_key)
                .unwrap()
                .is_closed()
        );
    }

    #[test]
    fn expires_idle_flows() {
        let mut table = FlowTable::new(
            10,
            Duration::from_secs(5),
        )
        .unwrap();

        let flow_key = key(1000, 443);

        table
            .record_packet(
                flow_key.clone(),
                100,
                FlowDirection::Forward,
                Some(1_000_000_000),
            )
            .unwrap();

        let expired =
            table.expire_idle(
                7_000_000_000
            );

        assert_eq!(expired, 1);
        assert_eq!(table.len(), 0);
        assert_eq!(
            table.stats().total_expired,
            1
        );
    }

    #[test]
    fn does_not_expire_active_flow() {
        let mut table = FlowTable::new(
            10,
            Duration::from_secs(5),
        )
        .unwrap();

        table
            .record_packet(
                key(1000, 443),
                100,
                FlowDirection::Forward,
                Some(1_000_000_000),
            )
            .unwrap();

        let expired =
            table.expire_idle(
                2_000_000_000
            );

        assert_eq!(expired, 0);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn clear_removes_all_flows() {
        let mut table = FlowTable::new(
            10,
            Duration::from_secs(30),
        )
        .unwrap();

        table
            .insert(Flow::new(key(1000, 443)))
            .unwrap();

        table
            .insert(Flow::new(key(1001, 443)))
            .unwrap();

        assert_eq!(table.clear(), 2);
        assert!(table.is_empty());
    }

    #[test]
    fn statistics_are_tracked() {
        let mut table = FlowTable::new(
            10,
            Duration::from_secs(30),
        )
        .unwrap();

        table
            .insert(Flow::new(key(1000, 443)))
            .unwrap();

        table
            .insert(Flow::new(key(1001, 443)))
            .unwrap();

        table.remove(&key(1000, 443));

        let stats = table.stats();

        assert_eq!(
            stats.current_entries,
            1
        );

        assert_eq!(
            stats.total_created,
            2
        );

        assert_eq!(
            stats.total_removed,
            1
        );
    }

    #[test]
    fn reports_available_capacity() {
        let mut table = FlowTable::new(
            3,
            Duration::from_secs(30),
        )
        .unwrap();

        assert_eq!(
            table.capacity_available(),
            3
        );

        table
            .insert(Flow::new(key(1000, 443)))
            .unwrap();

        assert_eq!(
            table.capacity_available(),
            2
        );
    }

    #[test]
    fn keys_returns_all_flow_keys() {
        let mut table = FlowTable::new(
            10,
            Duration::from_secs(30),
        )
        .unwrap();

        table
            .insert(Flow::new(key(1000, 443)))
            .unwrap();

        table
            .insert(Flow::new(key(1001, 443)))
            .unwrap();

        let keys = table.keys();

        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&key(1000, 443)));
        assert!(keys.contains(&key(1001, 443)));
    }
}