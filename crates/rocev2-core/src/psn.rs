//! Packet sequence number arithmetic for the 24-bit RC serial space.

/// Mask for the 24-bit packet sequence number carried by the BTH.
pub const PSN_MASK: u32 = 0x00ff_ffff;

/// Number of distinct values in the RC packet sequence number space.
pub const PSN_MODULUS: u32 = PSN_MASK + 1;

/// Relative ordering of two packet sequence numbers.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PsnOrdering {
    /// The left-hand PSN is before the reference PSN.
    Before,
    /// Both PSNs are equal.
    Equal,
    /// The left-hand PSN is after the reference PSN.
    After,
}

/// A validated 24-bit RC packet sequence number.
///
/// Serial-number ordering deliberately does not implement [`Ord`]: ordering in
/// a wrapping sequence space is only meaningful relative to a nearby
/// reference value.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct Psn(u32);

impl Psn {
    /// The first PSN in the sequence space.
    pub const ZERO: Self = Self(0);

    /// Construct a PSN when `value` fits in 24 bits.
    #[must_use]
    pub const fn new(value: u32) -> Option<Self> {
        if value <= PSN_MASK {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Construct a PSN by retaining the low 24 bits.
    ///
    /// This is intended for arithmetic and for decoding fields that have
    /// already been masked by the wire parser.
    #[must_use]
    pub const fn new_truncated(value: u32) -> Self {
        Self(value & PSN_MASK)
    }

    /// Return the numeric 24-bit value.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }

    /// Advance by `increment`, wrapping at 24 bits.
    #[must_use]
    pub const fn wrapping_add(self, increment: u32) -> Self {
        Self::new_truncated(self.0.wrapping_add(increment))
    }

    /// Return the next PSN.
    #[must_use]
    pub const fn next(self) -> Self {
        self.wrapping_add(1)
    }

    /// Return the forward modular distance from `older` to `self`.
    ///
    /// The result is in `0..=PSN_MASK`.
    #[must_use]
    pub const fn forward_distance_from(self, older: Self) -> u32 {
        self.0.wrapping_sub(older.0) & PSN_MASK
    }

    /// Compare this PSN with a nearby reference PSN.
    ///
    /// This follows the same signed 24-bit difference rule used by Linux RXE.
    /// Exactly half a sequence space is classified as [`PsnOrdering::Before`]
    /// to match that implementation.
    #[must_use]
    pub const fn compare(self, reference: Self) -> PsnOrdering {
        if self.0 == reference.0 {
            return PsnOrdering::Equal;
        }

        let shifted = (self.0.wrapping_sub(reference.0) & PSN_MASK) << 8;
        if (shifted & 0x8000_0000) != 0 {
            PsnOrdering::Before
        } else {
            PsnOrdering::After
        }
    }

    /// Return whether this PSN is before `reference` in serial order.
    #[must_use]
    pub const fn is_before(self, reference: Self) -> bool {
        matches!(self.compare(reference), PsnOrdering::Before)
    }

    /// Return whether this PSN is after `reference` in serial order.
    #[must_use]
    pub const fn is_after(self, reference: Self) -> bool {
        matches!(self.compare(reference), PsnOrdering::After)
    }
}

impl From<Psn> for u32 {
    fn from(value: Psn) -> Self {
        value.value()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_and_masks_values() {
        assert_eq!(Psn::new(PSN_MASK).unwrap().value(), PSN_MASK);
        assert!(Psn::new(PSN_MASK + 1).is_none());
        assert_eq!(Psn::new_truncated(PSN_MASK + 2).value(), 1);
    }

    #[test]
    fn arithmetic_wraps_at_24_bits() {
        assert_eq!(Psn::new(PSN_MASK).unwrap().next(), Psn::ZERO);
        assert_eq!(Psn::ZERO.wrapping_add(PSN_MODULUS + 7).value(), 7);
    }

    #[test]
    fn ordering_matches_wrapping_serial_arithmetic() {
        let last = Psn::new(PSN_MASK).unwrap();
        assert_eq!(Psn::ZERO.compare(last), PsnOrdering::After);
        assert_eq!(last.compare(Psn::ZERO), PsnOrdering::Before);
        assert_eq!(Psn::ZERO.compare(Psn::ZERO), PsnOrdering::Equal);
        assert_eq!(
            Psn::new_truncated(0x0080_0000).compare(Psn::ZERO),
            PsnOrdering::Before
        );
    }

    #[test]
    fn reports_forward_distance() {
        assert_eq!(
            Psn::new(5)
                .unwrap()
                .forward_distance_from(Psn::new(2).unwrap()),
            3
        );
        assert_eq!(
            Psn::ZERO.forward_distance_from(Psn::new(PSN_MASK).unwrap()),
            1
        );
    }
}
