//! Stable single-owner QPN assignment without locks or shared packet queues.

use crate::MAX_QPN;

/// A fixed QPN partition for independent endpoint owners.
///
/// This is control-plane assignment, not NIC steering. Configure RSS or hardware
/// flow rules so packets reach the owner's RX queue before XSKMAP redirection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpnShardPlan {
    shards: u32,
}

impl QpnShardPlan {
    /// Create a power-of-two partition of the 24-bit application QPN space.
    #[must_use]
    pub const fn new(shards: u32) -> Option<Self> {
        if shards == 0 || !shards.is_power_of_two() || shards > (1 << 16) {
            None
        } else {
            Some(Self { shards })
        }
    }

    /// Return the number of independent owners.
    #[must_use]
    pub const fn shards(self) -> u32 {
        self.shards
    }

    /// Return the stable owner of a valid application QPN.
    #[must_use]
    #[inline]
    pub const fn owner(self, qpn: u32) -> Option<u32> {
        if qpn < 2 || qpn > MAX_QPN {
            None
        } else {
            Some(qpn & (self.shards - 1))
        }
    }

    /// Assign the zero-based local ordinal to one owner without wrapping.
    ///
    /// QPNs 0 and 1 are always reserved; exhausted partitions return `None`.
    #[must_use]
    pub const fn qpn(self, owner: u32, ordinal: u32) -> Option<u32> {
        if owner >= self.shards {
            return None;
        }
        let first = if self.shards == 1 {
            2
        } else if owner < 2 {
            owner + self.shards
        } else {
            owner
        };
        if ordinal > (MAX_QPN - first) / self.shards {
            return None;
        }
        Some(first + ordinal * self.shards)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partitions_are_disjoint_and_never_wrap() {
        for shards in [1, 2, 4, 64, 65_536] {
            let plan = QpnShardPlan::new(shards).unwrap();
            for owner in 0..shards {
                let first = plan.qpn(owner, 0).unwrap();
                assert_eq!(plan.owner(first), Some(owner));
                let last = (MAX_QPN - first) / shards;
                assert_eq!(plan.owner(plan.qpn(owner, last).unwrap()), Some(owner));
                assert_eq!(plan.qpn(owner, last + 1), None);
                assert_eq!(plan.qpn(owner, u32::MAX), None);
            }
            assert_eq!(plan.qpn(shards, 0), None);
            assert_eq!(plan.owner(0), None);
            assert_eq!(plan.owner(1), None);
            assert_eq!(plan.owner(MAX_QPN + 1), None);
        }
        for shards in [0, 3, 65_537, u32::MAX] {
            assert!(QpnShardPlan::new(shards).is_none());
        }
    }
}
