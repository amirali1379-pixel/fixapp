use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;

#[derive(Debug)]
pub struct DedupFilter {
    seen: Mutex<DedupState>,
    max_size: usize,
}

#[derive(Debug, Default)]
struct DedupState {
    ids: HashSet<u64>,
    order: VecDeque<u64>,
}

impl DedupFilter {
    pub fn new(max_size: usize) -> Self {
        Self {
            seen: Mutex::new(DedupState {
                ids: HashSet::with_capacity(max_size),
                order: VecDeque::with_capacity(max_size),
            }),
            max_size,
        }
    }

    /// Returns true when `id` has already been observed in the bounded
    /// deduplication window. New IDs are retained until they age out of the
    /// window; the table is not globally cleared when capacity is reached.
    pub fn is_duplicate(&self, id: u64) -> bool {
        if self.max_size == 0 {
            return false;
        }

        let mut state = match self.seen.lock() {
            Ok(state) => state,
            Err(_) => return false,
        };

        if state.ids.contains(&id) {
            return true;
        }

        state.ids.insert(id);
        state.order.push_back(id);

        while state.order.len() > self.max_size {
            if let Some(expired) = state.order.pop_front() {
                state.ids.remove(&expired);
            }
        }

        false
    }

    pub fn clear(&self) {
        if let Ok(mut state) = self.seen.lock() {
            state.ids.clear();
            state.order.clear();
        }
    }

    pub fn len(&self) -> usize {
        self.seen
            .lock()
            .map(|state| state.ids.len())
            .unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for DedupFilter {
    fn default() -> Self {
        Self::new(8192)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_ids_are_rejected_within_window() {
        let filter = DedupFilter::new(2);
        assert!(!filter.is_duplicate(1));
        assert!(filter.is_duplicate(1));
        assert_eq!(filter.len(), 1);
    }

    #[test]
    fn oldest_id_expires_without_clearing_newer_ids() {
        let filter = DedupFilter::new(2);
        assert!(!filter.is_duplicate(1));
        assert!(!filter.is_duplicate(2));
        assert!(!filter.is_duplicate(3));
        assert_eq!(filter.len(), 2);
        assert!(!filter.is_duplicate(1));
        assert!(filter.is_duplicate(2));
        assert!(filter.is_duplicate(3));
    }

    #[test]
    fn zero_capacity_disables_deduplication() {
        let filter = DedupFilter::new(0);
        assert!(!filter.is_duplicate(1));
        assert!(!filter.is_duplicate(1));
        assert_eq!(filter.len(), 0);
    }

    #[test]
    fn clear_resets_both_membership_and_order() {
        let filter = DedupFilter::new(2);
        assert!(!filter.is_duplicate(1));
        assert!(!filter.is_duplicate(2));
        filter.clear();
        assert!(filter.is_empty());
        assert!(!filter.is_duplicate(1));
    }
}
