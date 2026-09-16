//! Fixed-capacity active-QP and deadline scheduling.
//!
//! Both schedulers are single-owner structures. They contain no locks, perform
//! no allocation, and are intended to be owned by one polling endpoint shard.

const NONE_INDEX: usize = usize::MAX;
const NONE_LINK: u32 = u32::MAX;
const NONE_POSITION: u32 = u32::MAX;

#[derive(Clone, Copy, Debug)]
struct ReadyLink {
    previous: u32,
    next: u32,
    queued: bool,
}

impl ReadyLink {
    const EMPTY: Self = Self {
        previous: NONE_LINK,
        next: NONE_LINK,
        queued: false,
    };
}

/// An intrusive FIFO of runnable QP slots.
///
/// Each possible QP slot owns one link, which makes scheduling, cancellation,
/// and removal O(1). Scheduling an already queued slot is a no-op, so one QP
/// cannot consume more than one queue entry.
#[derive(Debug)]
pub struct ReadyQueue<const N: usize> {
    links: [ReadyLink; N],
    head: usize,
    tail: usize,
    len: usize,
}

impl<const N: usize> ReadyQueue<N> {
    /// Create an empty ready queue.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            links: [ReadyLink::EMPTY; N],
            head: NONE_INDEX,
            tail: NONE_INDEX,
            len: 0,
        }
    }

    /// Return the compile-time number of schedulable QP slots.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Return the number of scheduled QP slots.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Return whether no QP slot is scheduled.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Return whether `slot` is currently scheduled.
    #[must_use]
    #[inline]
    pub fn is_scheduled(&self, slot: usize) -> bool {
        self.links.get(slot).is_some_and(|link| link.queued)
    }

    /// Add `slot` to the tail if it is valid and not already scheduled.
    ///
    /// Returns `true` only when a new entry was added. Slot indices equal to
    /// `u32::MAX` are reserved as the intrusive-link sentinel and rejected.
    #[inline]
    pub fn schedule(&mut self, slot: usize) -> bool {
        let Ok(slot_link) = u32::try_from(slot) else {
            return false;
        };
        if slot_link == NONE_LINK {
            return false;
        }
        let Some(link) = self.links.get(slot) else {
            return false;
        };
        if link.queued {
            return false;
        }

        let previous = self.tail;
        let previous_link = if previous == NONE_INDEX {
            NONE_LINK
        } else {
            let Ok(previous_link) = u32::try_from(previous) else {
                debug_assert!(false, "ready-queue index must fit its compact link");
                return false;
            };
            previous_link
        };
        self.links[slot] = ReadyLink {
            previous: previous_link,
            next: NONE_LINK,
            queued: true,
        };
        if previous == NONE_INDEX {
            self.head = slot;
        } else {
            self.links[previous].next = slot_link;
        }
        self.tail = slot;
        self.len += 1;
        true
    }

    /// Remove `slot` in O(1), preserving the order of all other entries.
    ///
    /// Returns `true` only when the slot had been scheduled.
    #[inline]
    pub fn cancel(&mut self, slot: usize) -> bool {
        let Some(link) = self.links.get(slot).copied() else {
            return false;
        };
        if !link.queued {
            return false;
        }

        let previous = decode_link(link.previous);
        let next = decode_link(link.next);
        if let Some(previous) = previous {
            self.links[previous].next = link.next;
        } else {
            self.head = next.unwrap_or(NONE_INDEX);
        }
        if let Some(next) = next {
            self.links[next].previous = link.previous;
        } else {
            self.tail = previous.unwrap_or(NONE_INDEX);
        }

        self.links[slot] = ReadyLink::EMPTY;
        self.len -= 1;
        true
    }

    /// Remove and return the oldest runnable QP slot.
    #[inline]
    pub fn pop(&mut self) -> Option<usize> {
        let slot = (self.head != NONE_INDEX).then_some(self.head)?;
        let removed = self.cancel(slot);
        debug_assert!(removed);
        Some(slot)
    }

    /// Remove every scheduled slot.
    pub fn clear(&mut self) {
        while self.pop().is_some() {}
    }
}

#[inline]
fn decode_link(link: u32) -> Option<usize> {
    (link != NONE_LINK)
        .then(|| usize::try_from(link).ok())
        .flatten()
}

impl<const N: usize> Default for ReadyQueue<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// One absolute QP deadline stored in [`TimerScheduler`].
///
/// Generation and sequence values let an endpoint reject an event that no
/// longer belongs to the current QP incarnation or timer arm operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimerEntry {
    deadline: u64,
    qp_slot: u32,
    qp_generation: u32,
    sequence: u32,
}

impl TimerEntry {
    const EMPTY: Self = Self {
        deadline: 0,
        qp_slot: 0,
        qp_generation: 0,
        sequence: 0,
    };

    /// Construct a timer event with stale-event identity fields.
    #[must_use]
    pub const fn new(deadline: u64, qp_slot: u32, qp_generation: u32, sequence: u32) -> Self {
        Self {
            deadline,
            qp_slot,
            qp_generation,
            sequence,
        }
    }

    /// Return the absolute deadline in caller-provided monotonic ticks.
    #[must_use]
    pub const fn deadline(self) -> u64 {
        self.deadline
    }

    /// Return the owning endpoint QP slot.
    #[must_use]
    pub const fn qp_slot(self) -> u32 {
        self.qp_slot
    }

    /// Return the QP generation captured when the timer was armed.
    #[must_use]
    pub const fn qp_generation(self) -> u32 {
        self.qp_generation
    }

    /// Return the per-QP timer arm sequence.
    #[must_use]
    pub const fn sequence(self) -> u32 {
        self.sequence
    }
}

/// An indexed, fixed-capacity binary min-heap of QP deadlines.
///
/// There is at most one entry for each QP slot. Updating or cancelling a
/// deadline is O(log N), retrieving the next deadline is O(1), and popping an
/// expired deadline is O(log N). The per-slot position index prevents lazy
/// stale entries from accumulating in fixed storage.
#[derive(Debug)]
pub struct TimerScheduler<const N: usize> {
    heap: [TimerEntry; N],
    positions: [u32; N],
    len: usize,
}

impl<const N: usize> TimerScheduler<N> {
    /// Create an empty deadline scheduler.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            heap: [TimerEntry::EMPTY; N],
            positions: [NONE_POSITION; N],
            len: 0,
        }
    }

    /// Return the maximum number of simultaneously armed QP timers.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Return the number of armed QP timers.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Return whether no QP timer is armed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Return the event currently associated with `qp_slot`.
    #[must_use]
    #[inline]
    pub fn get(&self, qp_slot: u32) -> Option<TimerEntry> {
        let slot = usize::try_from(qp_slot).ok()?;
        let position = *self.positions.get(slot)?;
        if position == NONE_POSITION {
            return None;
        }
        let position = usize::try_from(position).ok()?;
        if position < self.len {
            Some(self.heap[position])
        } else {
            None
        }
    }

    /// Insert or replace one QP timer.
    ///
    /// Returns `false` only if the entry names a slot outside this scheduler's
    /// capacity or the scheduler's compact position representation. A valid QP
    /// slot can always be scheduled because each slot has exactly one indexed
    /// heap position.
    #[inline]
    pub fn schedule(&mut self, entry: TimerEntry) -> bool {
        let Ok(slot) = usize::try_from(entry.qp_slot) else {
            return false;
        };
        let Some(&encoded_position) = self.positions.get(slot) else {
            return false;
        };

        if encoded_position != NONE_POSITION {
            let Ok(position) = usize::try_from(encoded_position) else {
                debug_assert!(false, "timer position must fit usize");
                return false;
            };
            if position >= self.len {
                debug_assert!(false, "timer position must reference the live heap");
                return false;
            }
            let previous = self.heap[position];
            self.heap[position] = entry;
            if precedes(entry, previous) {
                self.sift_up(position);
            } else if precedes(previous, entry) {
                self.sift_down(position);
            }
            return true;
        }

        if self.len == N {
            debug_assert!(false, "one-entry-per-QP timer heap cannot overflow");
            return false;
        }
        let Ok(position) = u32::try_from(self.len) else {
            return false;
        };
        if position == NONE_POSITION {
            return false;
        }
        self.heap[self.len] = entry;
        self.positions[slot] = position;
        self.len += 1;
        self.sift_up(self.len - 1);
        true
    }

    /// Cancel and return the timer associated with `qp_slot`.
    #[inline]
    pub fn cancel(&mut self, qp_slot: u32) -> Option<TimerEntry> {
        let slot = usize::try_from(qp_slot).ok()?;
        let position = *self.positions.get(slot)?;
        if position == NONE_POSITION {
            return None;
        }
        self.remove_at(usize::try_from(position).ok()?)
    }

    /// Borrow the earliest scheduled event.
    #[must_use]
    #[inline]
    pub fn peek(&self) -> Option<TimerEntry> {
        if self.len == 0 {
            None
        } else {
            Some(self.heap[0])
        }
    }

    /// Return the earliest absolute deadline.
    #[must_use]
    #[inline]
    pub fn next_deadline(&self) -> Option<u64> {
        self.peek().map(TimerEntry::deadline)
    }

    /// Remove and return the earliest event.
    #[inline]
    pub fn pop(&mut self) -> Option<TimerEntry> {
        (self.len != 0).then(|| self.remove_at(0)).flatten()
    }

    /// Remove the earliest event when its deadline is at or before `now`.
    #[inline]
    pub fn pop_expired(&mut self, now: u64) -> Option<TimerEntry> {
        let entry = self.peek()?;
        (entry.deadline <= now).then(|| self.pop()).flatten()
    }

    /// Cancel every timer.
    pub fn clear(&mut self) {
        while self.pop().is_some() {}
    }

    fn remove_at(&mut self, position: usize) -> Option<TimerEntry> {
        if position >= self.len {
            return None;
        }
        let removed = self.heap[position];
        let removed_slot = usize::try_from(removed.qp_slot).ok()?;
        *self.positions.get_mut(removed_slot)? = NONE_POSITION;

        self.len -= 1;
        if position == self.len {
            self.heap[self.len] = TimerEntry::EMPTY;
            return Some(removed);
        }

        let moved = self.heap[self.len];
        self.heap[self.len] = TimerEntry::EMPTY;
        self.heap[position] = moved;
        self.set_position(moved, position);

        if position != 0 {
            let parent = (position - 1) / 2;
            if self.entry_precedes(position, parent) {
                self.sift_up(position);
                return Some(removed);
            }
        }
        self.sift_down(position);
        Some(removed)
    }

    fn sift_up(&mut self, mut position: usize) {
        while position != 0 {
            let parent = (position - 1) / 2;
            if !self.entry_precedes(position, parent) {
                break;
            }
            self.swap_entries(position, parent);
            position = parent;
        }
    }

    fn sift_down(&mut self, mut position: usize) {
        loop {
            let left = position.saturating_mul(2).saturating_add(1);
            if left >= self.len {
                break;
            }
            let right = left + 1;
            let child = if right < self.len && self.entry_precedes(right, left) {
                right
            } else {
                left
            };
            if !self.entry_precedes(child, position) {
                break;
            }
            self.swap_entries(position, child);
            position = child;
        }
    }

    fn entry_precedes(&self, left: usize, right: usize) -> bool {
        precedes(self.heap[left], self.heap[right])
    }

    fn swap_entries(&mut self, left: usize, right: usize) {
        self.heap.swap(left, right);
        self.set_position(self.heap[left], left);
        self.set_position(self.heap[right], right);
    }

    fn set_position(&mut self, entry: TimerEntry, position: usize) {
        let Ok(slot) = usize::try_from(entry.qp_slot) else {
            debug_assert!(false, "timer QP slot must fit usize");
            return;
        };
        let Ok(position) = u32::try_from(position) else {
            debug_assert!(false, "timer heap position must fit u32");
            return;
        };
        if position == NONE_POSITION {
            debug_assert!(false, "timer heap position collides with sentinel");
            return;
        }
        if let Some(stored) = self.positions.get_mut(slot) {
            *stored = position;
        } else {
            debug_assert!(false, "timer QP slot must be in range");
        }
    }
}

impl<const N: usize> Default for TimerScheduler<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[inline]
const fn precedes(left: TimerEntry, right: TimerEntry) -> bool {
    if left.deadline != right.deadline {
        left.deadline < right.deadline
    } else if left.qp_slot != right.qp_slot {
        left.qp_slot < right.qp_slot
    } else if left.qp_generation != right.qp_generation {
        left.qp_generation < right.qp_generation
    } else {
        left.sequence < right.sequence
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn next_random(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[test]
    fn ready_queue_schedules_each_slot_once() {
        let mut ready = ReadyQueue::<4>::new();
        assert!(ready.schedule(2));
        assert!(!ready.schedule(2));
        assert!(ready.schedule(1));
        assert_eq!(ready.len(), 2);
        assert_eq!(ready.pop(), Some(2));
        assert_eq!(ready.pop(), Some(1));
        assert_eq!(ready.pop(), None);
    }

    #[test]
    fn ready_queue_cancels_in_constant_time_without_reordering() {
        let mut ready = ReadyQueue::<5>::new();
        assert!(ready.schedule(0));
        assert!(ready.schedule(1));
        assert!(ready.schedule(2));
        assert!(ready.cancel(1));
        assert!(!ready.is_scheduled(1));
        assert_eq!(ready.pop(), Some(0));
        assert_eq!(ready.pop(), Some(2));
    }

    #[test]
    fn ready_queue_requeues_at_tail_for_round_robin_fairness() {
        let mut ready = ReadyQueue::<3>::new();
        assert!(ready.schedule(0));
        assert!(ready.schedule(1));
        assert_eq!(ready.pop(), Some(0));
        assert!(ready.schedule(0));
        assert_eq!(ready.pop(), Some(1));
        assert_eq!(ready.pop(), Some(0));
    }

    #[test]
    fn zero_capacity_ready_queue_is_well_defined() {
        let mut ready = ReadyQueue::<0>::new();
        assert!(!ready.schedule(0));
        assert!(!ready.cancel(0));
        assert_eq!(ready.pop(), None);
    }

    #[test]
    fn ready_queue_matches_a_fifo_model_under_churn() {
        const CAPACITY: usize = 17;
        let mut ready = ReadyQueue::<CAPACITY>::new();
        let mut model = [NONE_INDEX; CAPACITY];
        let mut model_len = 0;
        let mut random = 0x4d59_5df4_d0f3_3173;

        for _ in 0..20_000 {
            let value = next_random(&mut random);
            let slot = usize::try_from(value % CAPACITY as u64).unwrap();
            match value % 3 {
                0 => {
                    let already_queued = model[..model_len].contains(&slot);
                    assert_eq!(ready.schedule(slot), !already_queued);
                    if !already_queued {
                        model[model_len] = slot;
                        model_len += 1;
                    }
                }
                1 => {
                    let position = model[..model_len].iter().position(|&entry| entry == slot);
                    assert_eq!(ready.cancel(slot), position.is_some());
                    if let Some(position) = position {
                        model.copy_within(position + 1..model_len, position);
                        model_len -= 1;
                        model[model_len] = NONE_INDEX;
                    }
                }
                _ => {
                    let expected = (model_len != 0).then_some(model[0]);
                    assert_eq!(ready.pop(), expected);
                    if model_len != 0 {
                        model.copy_within(1..model_len, 0);
                        model_len -= 1;
                        model[model_len] = NONE_INDEX;
                    }
                }
            }

            assert_eq!(ready.len(), model_len);
            for candidate in 0..CAPACITY {
                assert_eq!(
                    ready.is_scheduled(candidate),
                    model[..model_len].contains(&candidate),
                );
            }
        }
    }

    #[test]
    fn timer_scheduler_orders_and_updates_deadlines() {
        let mut timers = TimerScheduler::<4>::new();
        assert!(timers.schedule(TimerEntry::new(30, 2, 1, 1)));
        assert!(timers.schedule(TimerEntry::new(10, 0, 1, 1)));
        assert!(timers.schedule(TimerEntry::new(20, 1, 1, 1)));
        assert_eq!(timers.next_deadline(), Some(10));

        assert!(timers.schedule(TimerEntry::new(5, 2, 1, 2)));
        assert_eq!(timers.pop_expired(4), None);
        assert_eq!(timers.pop_expired(5), Some(TimerEntry::new(5, 2, 1, 2)));
        assert_eq!(timers.pop().map(TimerEntry::qp_slot), Some(0));
        assert_eq!(timers.pop().map(TimerEntry::qp_slot), Some(1));
    }

    #[test]
    fn timer_scheduler_keeps_one_entry_per_qp() {
        let mut timers = TimerScheduler::<1>::new();
        for sequence in 1..=100 {
            assert!(timers.schedule(TimerEntry::new(u64::from(100 - sequence), 0, 1, sequence,)));
            assert_eq!(timers.len(), 1);
        }
        assert_eq!(timers.get(0).map(TimerEntry::sequence), Some(100));
    }

    #[test]
    fn timer_scheduler_cancels_arbitrary_heap_positions() {
        let mut timers = TimerScheduler::<5>::new();
        for (slot, deadline) in [(0, 50), (1, 10), (2, 30), (3, 20), (4, 40)] {
            assert!(timers.schedule(TimerEntry::new(deadline, slot, 1, 1)));
        }
        assert_eq!(timers.cancel(2).map(TimerEntry::qp_slot), Some(2));
        assert_eq!(timers.cancel(1).map(TimerEntry::qp_slot), Some(1));
        assert_eq!(timers.next_deadline(), Some(20));
        assert_eq!(timers.len(), 3);
        assert!(timers.get(1).is_none());
        assert!(timers.get(2).is_none());
    }

    #[test]
    fn timer_scheduler_rejects_out_of_range_slots() {
        let mut timers = TimerScheduler::<1>::new();
        assert!(!timers.schedule(TimerEntry::new(1, 1, 1, 1)));
        assert_eq!(timers.cancel(1), None);
        assert_eq!(timers.len(), 0);
    }

    #[test]
    fn zero_capacity_timer_scheduler_is_well_defined() {
        let mut timers = TimerScheduler::<0>::new();
        assert!(!timers.schedule(TimerEntry::new(1, 0, 1, 1)));
        assert_eq!(timers.peek(), None);
        assert_eq!(timers.pop(), None);
        assert_eq!(timers.cancel(0), None);
    }

    #[test]
    fn timer_scheduler_matches_an_indexed_minimum_model_under_churn() {
        const CAPACITY: usize = 17;
        let mut timers = TimerScheduler::<CAPACITY>::new();
        let mut model = [None; CAPACITY];
        let mut random = 0xd1b5_4a32_d192_ed03;

        for sequence in 1..=20_000 {
            let value = next_random(&mut random);
            let slot = usize::try_from(value % CAPACITY as u64).unwrap();
            let qp_slot = u32::try_from(slot).unwrap();
            match value % 4 {
                0 | 1 => {
                    let entry = TimerEntry::new(
                        (value >> 8) % 257,
                        qp_slot,
                        u32::try_from((value >> 24) & 7).unwrap() + 1,
                        sequence,
                    );
                    assert!(timers.schedule(entry));
                    model[slot] = Some(entry);
                }
                2 => {
                    assert_eq!(timers.cancel(qp_slot), model[slot].take());
                }
                _ => {
                    let expected = model.iter().flatten().copied().min_by(|left, right| {
                        if precedes(*left, *right) {
                            core::cmp::Ordering::Less
                        } else if precedes(*right, *left) {
                            core::cmp::Ordering::Greater
                        } else {
                            core::cmp::Ordering::Equal
                        }
                    });
                    assert_eq!(timers.pop(), expected);
                    if let Some(entry) = expected {
                        model[usize::try_from(entry.qp_slot()).unwrap()] = None;
                    }
                }
            }

            let expected = model.iter().flatten().copied().min_by(|left, right| {
                if precedes(*left, *right) {
                    core::cmp::Ordering::Less
                } else if precedes(*right, *left) {
                    core::cmp::Ordering::Greater
                } else {
                    core::cmp::Ordering::Equal
                }
            });
            assert_eq!(timers.peek(), expected);
            assert_eq!(timers.len(), model.iter().flatten().count());
            for (slot, expected) in model.iter().copied().enumerate() {
                assert_eq!(timers.get(u32::try_from(slot).unwrap()), expected);
            }
        }
    }
}
