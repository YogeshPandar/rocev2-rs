//! Fixed-capacity queue-pair number lookup.

use core::fmt;

/// Largest queue-pair number carried by the 24-bit BTH field.
pub const MAX_QPN: u32 = 0x00ff_ffff;

const EMPTY_QPN: u32 = u32::MAX;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Entry {
    qpn: u32,
    slot: u32,
}

impl Entry {
    const EMPTY: Self = Self {
        qpn: EMPTY_QPN,
        slot: 0,
    };

    const fn is_empty(self) -> bool {
        self.qpn == EMPTY_QPN
    }
}

/// Failure returned by [`QpnTable::insert`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpnInsertError {
    /// The queue-pair number is wider than the 24-bit BTH field.
    InvalidQpn(u32),
    /// The queue-pair number is already present.
    Duplicate(u32),
    /// Every table entry is occupied.
    Full,
}

impl fmt::Display for QpnInsertError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidQpn(qpn) => write!(formatter, "QPN {qpn} exceeds 24 bits"),
            Self::Duplicate(qpn) => write!(formatter, "QPN {qpn} is already present"),
            Self::Full => formatter.write_str("QPN table is full"),
        }
    }
}

impl core::error::Error for QpnInsertError {}

/// Allocation-free open-addressed map from a 24-bit QPN to a QP slot.
///
/// Linear probing keeps each lookup contiguous in memory. Removal uses
/// backward shifting, so repeated QP churn does not accumulate tombstones.
/// A power-of-two capacity at least twice the maximum live entry count keeps
/// the load factor at or below 50 percent and enables mask-based bucketing.
#[derive(Debug)]
pub struct QpnTable<const N: usize> {
    entries: [Entry; N],
    len: usize,
}

impl<const N: usize> QpnTable<N> {
    /// Create an empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [Entry::EMPTY; N],
            len: 0,
        }
    }

    /// Return the compile-time entry capacity.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Return the number of live mappings.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Return whether the table has no mappings.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Return whether this capacity is suitable for `maximum_entries`.
    ///
    /// Suitable tables are powers of two with a load factor no greater than
    /// 50 percent. A zero-entry table accepts any capacity.
    #[must_use]
    pub const fn supports_entries(maximum_entries: usize) -> bool {
        maximum_entries == 0 || (N.is_power_of_two() && maximum_entries <= N / 2)
    }

    /// Look up the QP slot owning `qpn`.
    #[must_use]
    #[inline]
    pub fn get(&self, qpn: u32) -> Option<u32> {
        self.find_index(qpn).map(|index| self.entries[index].slot)
    }

    /// Insert a QPN-to-slot mapping.
    #[inline]
    pub fn insert(&mut self, qpn: u32, slot: u32) -> Result<(), QpnInsertError> {
        if qpn > MAX_QPN {
            return Err(QpnInsertError::InvalidQpn(qpn));
        }
        if N == 0 {
            return Err(QpnInsertError::Full);
        }

        let mut index = bucket::<N>(qpn);
        for _ in 0..N {
            let entry = self.entries[index];
            if entry.is_empty() {
                self.entries[index] = Entry { qpn, slot };
                self.len += 1;
                return Ok(());
            }
            if entry.qpn == qpn {
                return Err(QpnInsertError::Duplicate(qpn));
            }
            index = next_index::<N>(index);
        }
        Err(QpnInsertError::Full)
    }

    /// Remove `qpn` and return its QP slot.
    #[inline]
    pub fn remove(&mut self, qpn: u32) -> Option<u32> {
        let mut hole = self.find_index(qpn)?;
        let removed_slot = self.entries[hole].slot;
        let mut scan = next_index::<N>(hole);

        for _ in 1..N {
            let entry = self.entries[scan];
            if entry.is_empty() {
                break;
            }

            let home_index = bucket::<N>(entry.qpn);
            if probe_distance::<N>(home_index, hole) < probe_distance::<N>(home_index, scan) {
                self.entries[hole] = entry;
                hole = scan;
            }
            scan = next_index::<N>(scan);
        }

        self.entries[hole] = Entry::EMPTY;
        self.len -= 1;
        Some(removed_slot)
    }

    /// Remove every mapping.
    pub fn clear(&mut self) {
        self.entries.fill(Entry::EMPTY);
        self.len = 0;
    }

    #[inline]
    fn find_index(&self, qpn: u32) -> Option<usize> {
        if qpn > MAX_QPN || N == 0 {
            return None;
        }

        let mut index = bucket::<N>(qpn);
        for _ in 0..N {
            let entry = self.entries[index];
            if entry.is_empty() {
                return None;
            }
            if entry.qpn == qpn {
                return Some(index);
            }
            index = next_index::<N>(index);
        }
        None
    }
}

impl<const N: usize> Default for QpnTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[inline]
fn bucket<const N: usize>(qpn: u32) -> usize {
    debug_assert!(N != 0);
    let hash = mix_qpn(qpn) as usize;
    if N.is_power_of_two() {
        hash & (N - 1)
    } else {
        hash % N
    }
}

#[inline]
const fn mix_qpn(mut value: u32) -> u32 {
    value ^= value >> 16;
    value = value.wrapping_mul(0x7feb_352d);
    value ^= value >> 15;
    value = value.wrapping_mul(0x846c_a68b);
    value ^ (value >> 16)
}

#[inline]
const fn next_index<const N: usize>(index: usize) -> usize {
    debug_assert!(N != 0);
    if index + 1 == N { 0 } else { index + 1 }
}

#[inline]
const fn probe_distance<const N: usize>(home: usize, index: usize) -> usize {
    debug_assert!(N != 0);
    if index >= home {
        index - home
    } else {
        N - home + index
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn qpns_in_bucket<const N: usize>(target: usize, count: usize) -> [u32; 8] {
        assert!(count <= 8);
        let mut found = [0; 8];
        let mut length = 0;
        let mut qpn = 2;
        while length < count {
            if bucket::<N>(qpn) == target {
                found[length] = qpn;
                length += 1;
            }
            qpn += 1;
        }
        found
    }

    fn colliding_qpns<const N: usize>(count: usize) -> [u32; 8] {
        qpns_in_bucket::<N>(bucket::<N>(2), count)
    }

    #[test]
    fn inserts_looks_up_and_removes_mappings() {
        let mut table = QpnTable::<8>::new();
        table.insert(2, 7).unwrap();
        table.insert(3, 9).unwrap();

        assert_eq!(table.len(), 2);
        assert_eq!(table.get(2), Some(7));
        assert_eq!(table.get(3), Some(9));
        assert_eq!(table.remove(2), Some(7));
        assert_eq!(table.get(2), None);
        assert_eq!(table.get(3), Some(9));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn rejects_invalid_duplicate_and_full_inserts() {
        let mut table = QpnTable::<2>::new();
        assert_eq!(
            table.insert(MAX_QPN + 1, 0),
            Err(QpnInsertError::InvalidQpn(MAX_QPN + 1))
        );
        table.insert(2, 0).unwrap();
        assert_eq!(table.insert(2, 1), Err(QpnInsertError::Duplicate(2)));
        table.insert(3, 1).unwrap();
        assert_eq!(table.insert(4, 2), Err(QpnInsertError::Full));
    }

    #[test]
    fn backward_shift_preserves_colliding_cluster() {
        let qpns = colliding_qpns::<8>(4);
        let mut table = QpnTable::<8>::new();
        for (slot, qpn) in qpns[..4].iter().copied().enumerate() {
            table.insert(qpn, slot as u32).unwrap();
        }

        assert_eq!(table.remove(qpns[1]), Some(1));
        assert_eq!(table.get(qpns[0]), Some(0));
        assert_eq!(table.get(qpns[1]), None);
        assert_eq!(table.get(qpns[2]), Some(2));
        assert_eq!(table.get(qpns[3]), Some(3));
    }

    #[test]
    fn backward_shift_preserves_wrapped_cluster() {
        let qpns = qpns_in_bucket::<8>(7, 4);
        let mut table = QpnTable::<8>::new();
        for (slot, qpn) in qpns[..4].iter().copied().enumerate() {
            table.insert(qpn, slot as u32).unwrap();
        }

        assert_eq!(table.remove(qpns[0]), Some(0));
        assert_eq!(table.get(qpns[1]), Some(1));
        assert_eq!(table.get(qpns[2]), Some(2));
        assert_eq!(table.get(qpns[3]), Some(3));
    }

    #[test]
    fn removal_from_full_table_keeps_remaining_entries_reachable() {
        let mut table = QpnTable::<4>::new();
        for qpn in 2..6 {
            table.insert(qpn, qpn).unwrap();
        }

        assert_eq!(table.remove(3), Some(3));
        assert_eq!(table.get(2), Some(2));
        assert_eq!(table.get(4), Some(4));
        assert_eq!(table.get(5), Some(5));
    }

    #[test]
    fn repeated_churn_does_not_leave_tombstones() {
        let qpns = colliding_qpns::<16>(8);
        let mut table = QpnTable::<16>::new();

        for round in 0..4096_u32 {
            for (slot, qpn) in qpns.iter().copied().enumerate() {
                table.insert(qpn, slot as u32 + round).unwrap();
            }
            for qpn in qpns.iter().copied().step_by(2) {
                assert!(table.remove(qpn).is_some());
            }
            for qpn in qpns.iter().copied().step_by(2) {
                table.insert(qpn, round).unwrap();
            }
            for qpn in qpns {
                assert!(table.remove(qpn).is_some());
            }
            assert!(table.is_empty());
        }
    }

    #[test]
    fn zero_capacity_table_is_well_defined() {
        let mut table = QpnTable::<0>::new();
        assert!(table.is_empty());
        assert_eq!(table.get(2), None);
        assert_eq!(table.insert(2, 0), Err(QpnInsertError::Full));
        assert_eq!(table.remove(2), None);
        table.clear();
    }

    #[test]
    fn reports_recommended_capacity() {
        assert!(QpnTable::<8>::supports_entries(4));
        assert!(!QpnTable::<8>::supports_entries(5));
        assert!(!QpnTable::<6>::supports_entries(3));
        assert!(QpnTable::<0>::supports_entries(0));
    }
}
