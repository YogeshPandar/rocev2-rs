//! Fixed-capacity full-width protection-key lookup.

use crate::{MemoryError, mix32};

/// Caller-supplied key source; production implementations should use a CSPRNG.
///
/// The registry rejects zero and live collisions with a bounded retry count.
/// A 32-bit key is not authentication. A source that reissues a retired key can
/// make that key valid again; applications must quiesce peers before reuse.
pub trait KeyGenerator {
    /// Produce the next candidate or report an entropy-source failure.
    fn next_key(&mut self) -> Result<u32, MemoryError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KeyKind {
    Local,
    Remote,
}

#[derive(Clone, Copy)]
struct Entry {
    key: u32,
    slot: u16,
    kind: KeyKind,
}

impl Entry {
    const EMPTY: Self = Self {
        key: 0,
        slot: 0,
        kind: KeyKind::Local,
    };
}

pub(crate) struct KeyTable<const N: usize> {
    // Four buckets per MR keep the two-key table at most half full.
    entries: [[Entry; 4]; N],
}

impl<const N: usize> KeyTable<N> {
    pub(crate) const fn new() -> Self {
        Self {
            entries: [[Entry::EMPTY; 4]; N],
        }
    }

    fn entry(&self, index: usize) -> Entry {
        self.entries[index / 4][index % 4]
    }

    fn set(&mut self, index: usize, entry: Entry) {
        self.entries[index / 4][index % 4] = entry;
    }

    fn position(&self, key: u32) -> Option<usize> {
        let capacity = N * 4;
        if capacity == 0 || key == 0 {
            return None;
        }
        let mut index = mix32(key) as usize % capacity;
        for _ in 0..capacity {
            let entry = self.entry(index);
            if entry.key == key {
                return Some(index);
            }
            if entry.key == 0 {
                return None;
            }
            index = (index + 1) % capacity;
        }
        None
    }

    pub(crate) fn contains(&self, key: u32) -> bool {
        self.position(key).is_some()
    }

    pub(crate) fn get(&self, key: u32, kind: KeyKind) -> Option<usize> {
        let entry = self.entry(self.position(key)?);
        (entry.kind == kind).then_some(usize::from(entry.slot))
    }

    pub(crate) fn insert(&mut self, key: u32, slot: u16, kind: KeyKind) -> bool {
        let capacity = N * 4;
        if capacity == 0 || key == 0 {
            return false;
        }
        let mut index = mix32(key) as usize % capacity;
        for _ in 0..capacity {
            let entry = self.entry(index);
            if entry.key == key {
                return false;
            }
            if entry.key == 0 {
                self.set(index, Entry { key, slot, kind });
                return true;
            }
            index = (index + 1) % capacity;
        }
        false
    }

    pub(crate) fn remove(&mut self, key: u32) {
        let Some(mut index) = self.position(key) else {
            return;
        };
        self.set(index, Entry::EMPTY);
        // Reinsert the cluster so deletion never leaves a lookup-breaking hole.
        for _ in 0..N * 4 {
            index = (index + 1) % (N * 4);
            let entry = self.entry(index);
            if entry.key == 0 {
                break;
            }
            self.set(index, Entry::EMPTY);
            let inserted = self.insert(entry.key, entry.slot, entry.kind);
            debug_assert!(inserted);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colliding_keys_survive_cluster_deletion_and_reuse() {
        let mut table = KeyTable::<4>::new();
        let mut keys = [0; 8];
        let mut count = 0;
        for key in 1..10_000 {
            if mix32(key) % 16 == 15 {
                keys[count] = key;
                count += 1;
                if count == keys.len() {
                    break;
                }
            }
        }
        assert_eq!(count, keys.len());
        for (slot, &key) in keys.iter().enumerate() {
            assert!(table.insert(key, slot as u16, KeyKind::Remote));
            assert_eq!(table.get(key, KeyKind::Local), None);
        }
        for &key in &keys[..4] {
            table.remove(key);
        }
        for (slot, &key) in keys.iter().enumerate().skip(4) {
            assert_eq!(table.get(key, KeyKind::Remote), Some(slot));
        }
        for &key in &keys[..4] {
            assert!(table.insert(key, 0, KeyKind::Local));
        }
        for &key in &keys {
            assert!(table.contains(key));
        }
    }

    #[test]
    fn zero_capacity_and_zero_key_are_rejected() {
        let mut table = KeyTable::<0>::new();
        assert!(!table.insert(1, 0, KeyKind::Local));
        assert!(!table.contains(1));
        table.remove(1);
        assert!(!KeyTable::<1>::new().insert(0, 0, KeyKind::Local));
    }
}
