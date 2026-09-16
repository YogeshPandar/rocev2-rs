//! Fixed-capacity single-owner ring storage.

/// Error returned when an item cannot be pushed into a full ring.
#[derive(Debug, Eq, PartialEq)]
pub enum PushError<T> {
    /// The ring is full; ownership of the item is returned to the caller.
    Full(T),
}

impl<T> PushError<T> {
    /// Recover the item that could not be inserted.
    #[must_use]
    pub fn into_inner(self) -> T {
        match self {
            Self::Full(item) => item,
        }
    }
}

/// A fixed-capacity FIFO ring with no heap allocation.
///
/// This type is intentionally single-owner and contains no synchronization.
/// A polling data plane can assign one ring to one core and provide any
/// cross-core synchronization at a higher layer.
#[derive(Debug)]
pub struct Ring<T, const N: usize> {
    slots: [Option<T>; N],
    head: usize,
    tail: usize,
    len: usize,
}

impl<T, const N: usize> Ring<T, N> {
    /// Create an empty ring.
    #[must_use]
    pub fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| None),
            head: 0,
            tail: 0,
            len: 0,
        }
    }

    /// Return the compile-time capacity.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Return the number of occupied entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Return whether the ring contains no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Return whether the ring is at capacity.
    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.len == N
    }

    /// Return the number of additional elements that can be queued.
    #[must_use]
    pub const fn remaining_capacity(&self) -> usize {
        N - self.len
    }

    /// Borrow the element at `offset` relative to the current head.
    #[must_use]
    pub fn get(&self, offset: usize) -> Option<&T> {
        if offset >= self.len || N == 0 {
            return None;
        }
        self.slots[(self.head + offset) % N].as_ref()
    }

    /// Insert an item at the producer end.
    pub fn push(&mut self, item: T) -> Result<(), PushError<T>> {
        if self.is_full() {
            return Err(PushError::Full(item));
        }

        debug_assert!(N != 0);
        debug_assert!(self.slots[self.tail].is_none());
        self.slots[self.tail] = Some(item);
        self.tail = (self.tail + 1) % N;
        self.len += 1;
        Ok(())
    }

    /// Remove and return the oldest item.
    pub fn pop(&mut self) -> Option<T> {
        if self.is_empty() {
            return None;
        }

        debug_assert!(N != 0);
        let item = self.slots[self.head].take();
        self.head = (self.head + 1) % N;
        self.len -= 1;
        item
    }

    /// Borrow the oldest item.
    #[must_use]
    pub fn front(&self) -> Option<&T> {
        if self.is_empty() {
            None
        } else {
            self.slots[self.head].as_ref()
        }
    }

    /// Mutably borrow the oldest item.
    #[must_use]
    pub fn front_mut(&mut self) -> Option<&mut T> {
        if self.is_empty() {
            None
        } else {
            self.slots[self.head].as_mut()
        }
    }

    /// Remove all entries in FIFO order.
    pub fn clear(&mut self) {
        while self.pop().is_some() {}
    }
}

impl<T, const N: usize> Default for Ring<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_fifo_order_across_wrap() {
        let mut ring = Ring::<u32, 3>::new();
        ring.push(1).unwrap();
        ring.push(2).unwrap();
        assert_eq!(ring.pop(), Some(1));
        ring.push(3).unwrap();
        ring.push(4).unwrap();

        assert_eq!(ring.pop(), Some(2));
        assert_eq!(ring.pop(), Some(3));
        assert_eq!(ring.pop(), Some(4));
        assert_eq!(ring.pop(), None);
    }

    #[test]
    fn get_indexes_from_head_across_wrap() {
        let mut ring = Ring::<u32, 3>::new();
        ring.push(1).unwrap();
        ring.push(2).unwrap();
        assert_eq!(ring.pop(), Some(1));
        ring.push(3).unwrap();
        ring.push(4).unwrap();
        assert_eq!(ring.get(0), Some(&2));
        assert_eq!(ring.get(1), Some(&3));
        assert_eq!(ring.get(2), Some(&4));
        assert_eq!(ring.get(3), None);
        assert_eq!(ring.remaining_capacity(), 0);
    }

    #[test]
    fn returns_item_when_full() {
        let mut ring = Ring::<u32, 1>::new();
        ring.push(7).unwrap();
        assert_eq!(ring.push(8), Err(PushError::Full(8)));
        assert_eq!(ring.front(), Some(&7));
    }

    #[test]
    fn zero_capacity_ring_is_well_defined() {
        let mut ring = Ring::<u32, 0>::new();
        assert!(ring.is_empty());
        assert!(ring.is_full());
        assert_eq!(ring.push(1), Err(PushError::Full(1)));
        assert_eq!(ring.pop(), None);
    }

    #[test]
    fn clear_drops_every_entry() {
        let mut ring = Ring::<u32, 4>::new();
        ring.push(1).unwrap();
        ring.push(2).unwrap();
        ring.clear();
        assert!(ring.is_empty());
        assert_eq!(ring.front(), None);
    }
}
