#![forbid(unsafe_code)]

use network_core::EngineError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WfpFlowState {
    Unknown = 0,
    New = 1,
    Established = 2,
    Closing = 3,
    Closed = 4,
    Aborted = 5,
}

impl WfpFlowState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Closed | Self::Aborted
        )
    }

    pub fn is_active(self) -> bool {
        matches!(
            self,
            Self::New
                | Self::Established
                | Self::Closing
        )
    }

    pub fn can_transition_to(
        self,
        next: Self,
    ) -> bool {
        match (self, next) {
            (a, b) if a == b => true,

            (Self::Unknown, Self::New) => true,
            (Self::Unknown, Self::Established) => true,

            (Self::New, Self::Established) => true,
            (Self::New, Self::Closing) => true,
            (Self::New, Self::Aborted) => true,

            (Self::Established, Self::Closing) => true,
            (Self::Established, Self::Closed) => true,
            (Self::Established, Self::Aborted) => true,

            (Self::Closing, Self::Closed) => true,
            (Self::Closing, Self::Aborted) => true,

            _ => false,
        }
    }
}

impl TryFrom<u8> for WfpFlowState {
    type Error = EngineError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Unknown),
            1 => Ok(Self::New),
            2 => Ok(Self::Established),
            3 => Ok(Self::Closing),
            4 => Ok(Self::Closed),
            5 => Ok(Self::Aborted),
            _ => Err(EngineError::invalid_argument()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfpFlow {
    pub flow_id: u64,
    pub filter_id: Option<u64>,
    pub process_id: Option<u32>,
    pub local_address: Option<Vec<u8>>,
    pub remote_address: Option<Vec<u8>>,
    pub local_port: Option<u16>,
    pub remote_port: Option<u16>,
    pub protocol: u8,
    pub state: WfpFlowState,
    pub packet_count: u64,
    pub byte_count: u64,
    pub created_at_ns: u64,
    pub last_seen_ns: u64,
}

impl WfpFlow {
    pub fn new(
        flow_id: u64,
        protocol: u8,
        timestamp_ns: u64,
    ) -> Result<Self, EngineError> {
        if flow_id == 0 {
            return Err(
                EngineError::invalid_argument()
            );
        }

        Ok(Self {
            flow_id,
            filter_id: None,
            process_id: None,
            local_address: None,
            remote_address: None,
            local_port: None,
            remote_port: None,
            protocol,
            state: WfpFlowState::New,
            packet_count: 0,
            byte_count: 0,
            created_at_ns: timestamp_ns,
            last_seen_ns: timestamp_ns,
        })
    }

    pub fn set_filter_id(
        &mut self,
        filter_id: Option<u64>,
    ) {
        self.filter_id = filter_id;
    }

    pub fn set_process_id(
        &mut self,
        process_id: Option<u32>,
    ) {
        self.process_id = process_id;
    }

    pub fn set_local_address(
        &mut self,
        address: Vec<u8>,
    ) {
        self.local_address = Some(address);
    }

    pub fn set_remote_address(
        &mut self,
        address: Vec<u8>,
    ) {
        self.remote_address = Some(address);
    }

    pub fn set_ports(
        &mut self,
        local: u16,
        remote: u16,
    ) {
        self.local_port = Some(local);
        self.remote_port = Some(remote);
    }

    pub fn transition(
        &mut self,
        next: WfpFlowState,
    ) -> Result<(), EngineError> {
        if !self.state.can_transition_to(next) {
            return Err(
                EngineError::backend(
                    network_core::EngineErrorCode::InvalidStateTransition,
                    "wfp",
                )
            );
        }

        self.state = next;
        Ok(())
    }

    pub fn record_packet(
        &mut self,
        bytes: u64,
        timestamp_ns: u64,
    ) -> Result<(), EngineError> {
        if self.state.is_terminal() {
            return Err(
                EngineError::backend(
                    network_core::EngineErrorCode::InvalidStateTransition,
                    "wfp",
                )
            );
        }

        self.packet_count =
            self.packet_count
                .checked_add(1)
                .ok_or_else(|| {
                    EngineError::integer_overflow()
                })?;

        self.byte_count =
            self.byte_count
                .checked_add(bytes)
                .ok_or_else(|| {
                    EngineError::integer_overflow()
                })?;

        self.last_seen_ns = timestamp_ns;

        if self.state == WfpFlowState::New {
            self.state =
                WfpFlowState::Established;
        }

        Ok(())
    }

    pub fn age_ns(
        &self,
        now_ns: u64,
    ) -> u64 {
        now_ns.saturating_sub(
            self.created_at_ns
        )
    }

    pub fn idle_ns(
        &self,
        now_ns: u64,
    ) -> u64 {
        now_ns.saturating_sub(
            self.last_seen_ns
        )
    }

    pub fn is_idle(
        &self,
        now_ns: u64,
        timeout_ns: u64,
    ) -> bool {
        self.idle_ns(now_ns) >= timeout_ns
    }

    pub fn close(
        &mut self,
    ) -> Result<(), EngineError> {
        if self.state == WfpFlowState::Closed {
            return Ok(());
        }

        if self.state == WfpFlowState::Aborted {
            return Err(
                EngineError::backend(
                    network_core::EngineErrorCode::InvalidStateTransition,
                    "wfp",
                )
            );
        }

        if self.state != WfpFlowState::Closing {
            self.transition(
                WfpFlowState::Closing
            )?;
        }

        self.transition(
            WfpFlowState::Closed
        )
    }

    pub fn abort(
        &mut self,
    ) -> Result<(), EngineError> {
        if self.state.is_terminal() {
            return Ok(());
        }

        self.transition(
            WfpFlowState::Aborted
        )
    }
}

#[derive(Debug, Default)]
pub struct WfpFlowTable {
    flows: std::collections::HashMap<u64, WfpFlow>,
    max_entries: usize,
}

impl WfpFlowTable {
    pub fn new(
        max_entries: usize,
    ) -> Result<Self, EngineError> {
        if max_entries == 0 {
            return Err(
                EngineError::invalid_argument()
            );
        }

        Ok(Self {
            flows: std::collections::HashMap::new(),
            max_entries,
        })
    }

    pub fn with_default_capacity() -> Self {
        Self {
            flows: std::collections::HashMap::new(),
            max_entries: 100_000,
        }
    }

    pub fn insert(
        &mut self,
        flow: WfpFlow,
    ) -> Result<(), EngineError> {
        if self.flows.contains_key(
            &flow.flow_id
        ) {
            return Err(
                EngineError::invalid_argument()
            );
        }

        if self.flows.len()
            >= self.max_entries
        {
            return Err(
                EngineError::resource_exhausted()
            );
        }

        self.flows.insert(
            flow.flow_id,
            flow
        );

        Ok(())
    }

    pub fn get(
        &self,
        flow_id: u64,
    ) -> Option<&WfpFlow> {
        self.flows.get(&flow_id)
    }

    pub fn get_mut(
        &mut self,
        flow_id: u64,
    ) -> Option<&mut WfpFlow> {
        self.flows.get_mut(&flow_id)
    }

    pub fn remove(
        &mut self,
        flow_id: u64,
    ) -> Option<WfpFlow> {
        self.flows.remove(&flow_id)
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

    pub fn contains(
        &self,
        flow_id: u64,
    ) -> bool {
        self.flows.contains_key(&flow_id)
    }

    pub fn values(
        &self,
    ) -> impl Iterator<Item = &WfpFlow> {
        self.flows.values()
    }

    pub fn expire_idle(
        &mut self,
        now_ns: u64,
        timeout_ns: u64,
    ) -> usize {
        let expired: Vec<u64> = self
            .flows
            .iter()
            .filter_map(|(id, flow)| {
                if flow.is_idle(
                    now_ns,
                    timeout_ns
                ) {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect();

        let count = expired.len();

        for id in expired {
            self.flows.remove(&id);
        }

        count
    }

    pub fn clear(&mut self) {
        self.flows.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_flow() {
        let flow =
            WfpFlow::new(
                1,
                6,
                100,
            )
            .unwrap();

        assert_eq!(
            flow.flow_id,
            1
        );

        assert_eq!(
            flow.protocol,
            6
        );

        assert_eq!(
            flow.state,
            WfpFlowState::New
        );
    }

    #[test]
    fn invalid_flow_id_is_rejected() {
        assert!(
            WfpFlow::new(
                0,
                6,
                0
            )
            .is_err()
        );
    }

    #[test]
    fn packet_record_updates_flow() {
        let mut flow =
            WfpFlow::new(
                1,
                6,
                100,
            )
            .unwrap();

        flow.record_packet(
            100,
            200,
        )
        .unwrap();

        flow.record_packet(
            200,
            300,
        )
        .unwrap();

        assert_eq!(
            flow.packet_count,
            2
        );

        assert_eq!(
            flow.byte_count,
            300
        );

        assert_eq!(
            flow.state,
            WfpFlowState::Established
        );

        assert_eq!(
            flow.last_seen_ns,
            300
        );
    }

    #[test]
    fn flow_state_transition() {
        let mut flow =
            WfpFlow::new(
                1,
                6,
                0,
            )
            .unwrap();

        flow.transition(
            WfpFlowState::Established
        )
        .unwrap();

        flow.transition(
            WfpFlowState::Closing
        )
        .unwrap();

        flow.transition(
            WfpFlowState::Closed
        )
        .unwrap();

        assert!(
            flow.state.is_terminal()
        );
    }

    #[test]
    fn closed_flow_rejects_packets() {
        let mut flow =
            WfpFlow::new(
                1,
                6,
                0,
            )
            .unwrap();

        flow.close().unwrap();

        assert!(
            flow.record_packet(
                100,
                100
            )
            .is_err()
        );
    }

    #[test]
    fn idle_calculation_is_safe() {
        let flow =
            WfpFlow::new(
                1,
                6,
                100,
            )
            .unwrap();

        assert_eq!(
            flow.age_ns(50),
            0
        );

        assert_eq!(
            flow.idle_ns(50),
            0
        );

        assert!(
            flow.is_idle(
                1_100,
                1_000
            )
        );
    }

    #[test]
    fn flow_table_insert_and_lookup() {
        let mut table =
            WfpFlowTable::new(10)
                .unwrap();

        let flow =
            WfpFlow::new(
                1,
                6,
                0,
            )
            .unwrap();

        table.insert(flow).unwrap();

        assert_eq!(
            table.len(),
            1
        );

        assert!(
            table.contains(1)
        );

        assert_eq!(
            table.get(1).unwrap().flow_id,
            1
        );
    }

    #[test]
    fn flow_table_rejects_duplicate() {
        let mut table =
            WfpFlowTable::new(10)
                .unwrap();

        table
            .insert(
                WfpFlow::new(
                    1,
                    6,
                    0,
                )
                .unwrap()
            )
            .unwrap();

        assert!(
            table
                .insert(
                    WfpFlow::new(
                        1,
                        17,
                        0,
                    )
                    .unwrap()
                )
                .is_err()
        );
    }

    #[test]
    fn flow_table_respects_capacity() {
        let mut table =
            WfpFlowTable::new(1)
                .unwrap();

        table
            .insert(
                WfpFlow::new(
                    1,
                    6,
                    0,
                )
                .unwrap()
            )
            .unwrap();

        let result =
            table.insert(
                WfpFlow::new(
                    2,
                    6,
                    0,
                )
                .unwrap()
            );

        assert_eq!(
            result.unwrap_err().code(),
            network_core::EngineErrorCode::ResourceExhausted
        );
    }

    #[test]
    fn idle_flows_are_expired() {
        let mut table =
            WfpFlowTable::new(10)
                .unwrap();

        table
            .insert(
                WfpFlow::new(
                    1,
                    6,
                    0,
                )
                .unwrap()
            )
            .unwrap();

        table
            .insert(
                WfpFlow::new(
                    2,
                    6,
                    900,
                )
                .unwrap()
            )
            .unwrap();

        let expired =
            table.expire_idle(
                1_000,
                500,
            );

        assert_eq!(
            expired,
            1
        );

        assert!(
            !table.contains(1)
        );

        assert!(
            table.contains(2)
        );
    }

    #[test]
    fn abort_flow() {
        let mut flow =
            WfpFlow::new(
                1,
                17,
                0,
            )
            .unwrap();

        flow.abort().unwrap();

        assert_eq!(
            flow.state,
            WfpFlowState::Aborted
        );

        assert!(
            flow.state.is_terminal()
        );
    }
}