//! ACK processing and receive-side PSN classification.

use crate::{PSN_MODULUS, Psn, PsnOrdering};

const MAX_OUTSTANDING_PACKETS: u32 = (PSN_MODULUS / 2) - 1;

/// Result of processing a cumulative ACK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AckAdvance {
    /// The ACK advanced the send window.
    Advanced {
        /// Number of newly acknowledged packets.
        packets: u32,
        /// First PSN that remains unacknowledged.
        next_unacknowledged: Psn,
    },
    /// The ACK covers only packets that were already acknowledged.
    Duplicate,
    /// The ACK names a packet that has not been sent.
    Invalid,
}

/// Classification of an incoming request PSN.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveDisposition {
    /// The packet is exactly the next packet expected.
    Expected,
    /// The packet precedes the next expected PSN and is a duplicate.
    Duplicate,
    /// The packet is ahead of the next expected PSN.
    Future,
}

/// Receive-side expected-PSN tracker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivePsn {
    expected: Psn,
}

impl ReceivePsn {
    /// Create a receive tracker at `expected`.
    #[must_use]
    pub const fn new(expected: Psn) -> Self {
        Self { expected }
    }

    /// Return the PSN required for the next in-order packet.
    #[must_use]
    pub const fn expected(self) -> Psn {
        self.expected
    }

    /// Classify a PSN without changing receive state.
    #[must_use]
    pub const fn classify(self, received: Psn) -> ReceiveDisposition {
        match received.compare(self.expected) {
            PsnOrdering::Equal => ReceiveDisposition::Expected,
            PsnOrdering::Before => ReceiveDisposition::Duplicate,
            PsnOrdering::After => ReceiveDisposition::Future,
        }
    }

    /// Classify a PSN and advance state for an in-order packet.
    pub fn observe(&mut self, received: Psn) -> ReceiveDisposition {
        let disposition = self.classify(received);
        if matches!(disposition, ReceiveDisposition::Expected) {
            self.expected = self.expected.next();
        }
        disposition
    }

    /// Reset the receive tracker after a QP reset or reconfiguration.
    pub const fn reset(&mut self, expected: Psn) {
        self.expected = expected;
    }
}

/// Cumulative-ACK window for transmitted request packets.
///
/// The window is deliberately bounded to less than half the PSN sequence
/// space, which keeps serial-number comparisons unambiguous.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendWindow {
    oldest_unacknowledged: Psn,
    next_to_send: Psn,
}

impl SendWindow {
    /// Create an empty window whose first packet will use `initial_psn`.
    #[must_use]
    pub const fn new(initial_psn: Psn) -> Self {
        Self {
            oldest_unacknowledged: initial_psn,
            next_to_send: initial_psn,
        }
    }

    /// Return the first PSN that has not been acknowledged.
    #[must_use]
    pub const fn oldest_unacknowledged(self) -> Psn {
        self.oldest_unacknowledged
    }

    /// Return the PSN that will be assigned to the next packet.
    #[must_use]
    pub const fn next_to_send(self) -> Psn {
        self.next_to_send
    }

    /// Return the number of packets currently outstanding.
    #[must_use]
    pub const fn outstanding(self) -> u32 {
        self.next_to_send
            .forward_distance_from(self.oldest_unacknowledged)
    }

    /// Reserve and return the next PSN, or `None` if the safe window is full.
    pub fn reserve(&mut self) -> Option<Psn> {
        if self.outstanding() >= MAX_OUTSTANDING_PACKETS {
            return None;
        }

        let reserved = self.next_to_send;
        self.next_to_send = self.next_to_send.next();
        Some(reserved)
    }

    /// Process a cumulative ACK naming the last packet received by the peer.
    pub fn acknowledge(&mut self, acknowledged: Psn) -> AckAdvance {
        if matches!(
            acknowledged.compare(self.oldest_unacknowledged),
            PsnOrdering::Before
        ) {
            return AckAdvance::Duplicate;
        }

        if !matches!(acknowledged.compare(self.next_to_send), PsnOrdering::Before) {
            return AckAdvance::Invalid;
        }

        let packets = acknowledged.forward_distance_from(self.oldest_unacknowledged) + 1;
        self.oldest_unacknowledged = acknowledged.next();
        AckAdvance::Advanced {
            packets,
            next_unacknowledged: self.oldest_unacknowledged,
        }
    }

    /// Reset the send window after QP reset or reconnection.
    pub const fn reset(&mut self, initial_psn: Psn) {
        self.oldest_unacknowledged = initial_psn;
        self.next_to_send = initial_psn;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PSN_MASK;

    #[test]
    fn receive_tracker_classifies_and_advances() {
        let mut receive = ReceivePsn::new(Psn::new(10).unwrap());

        assert_eq!(
            receive.observe(Psn::new(11).unwrap()),
            ReceiveDisposition::Future
        );
        assert_eq!(
            receive.observe(Psn::new(10).unwrap()),
            ReceiveDisposition::Expected
        );
        assert_eq!(
            receive.observe(Psn::new(10).unwrap()),
            ReceiveDisposition::Duplicate
        );
        assert_eq!(receive.expected(), Psn::new(11).unwrap());
    }

    #[test]
    fn cumulative_ack_advances_multiple_packets() {
        let mut window = SendWindow::new(Psn::new(20).unwrap());
        assert_eq!(window.reserve(), Psn::new(20));
        assert_eq!(window.reserve(), Psn::new(21));
        assert_eq!(window.reserve(), Psn::new(22));

        assert_eq!(
            window.acknowledge(Psn::new(21).unwrap()),
            AckAdvance::Advanced {
                packets: 2,
                next_unacknowledged: Psn::new(22).unwrap(),
            }
        );
        assert_eq!(window.outstanding(), 1);
        assert_eq!(
            window.acknowledge(Psn::new(20).unwrap()),
            AckAdvance::Duplicate
        );
        assert_eq!(
            window.acknowledge(Psn::new(23).unwrap()),
            AckAdvance::Invalid
        );
    }

    #[test]
    fn send_window_handles_rollover() {
        let mut window = SendWindow::new(Psn::new(PSN_MASK).unwrap());
        assert_eq!(window.reserve(), Psn::new(PSN_MASK));
        assert_eq!(window.reserve(), Some(Psn::ZERO));
        assert_eq!(
            window.acknowledge(Psn::new(PSN_MASK).unwrap()),
            AckAdvance::Advanced {
                packets: 1,
                next_unacknowledged: Psn::ZERO,
            }
        );
        assert_eq!(window.outstanding(), 1);
    }

    #[test]
    fn empty_window_rejects_unsent_ack() {
        let mut window = SendWindow::new(Psn::new(7).unwrap());
        assert_eq!(
            window.acknowledge(Psn::new(7).unwrap()),
            AckAdvance::Invalid
        );
    }
}
