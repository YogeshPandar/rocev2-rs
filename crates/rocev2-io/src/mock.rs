//! Deterministic in-memory packet I/O for tests and simulation.

use crate::PacketIo;
use std::collections::VecDeque;
use std::fmt;

/// Owned complete IPv4 packet used by [`MockIo`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    bytes: Box<[u8]>,
}

impl Frame {
    /// Copy bytes into an owned mock frame.
    #[must_use]
    pub fn copy_from_slice(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    /// Return the complete IPv4 packet bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Return the frame length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return whether the frame has no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Consume the frame and return its boxed bytes.
    #[must_use]
    pub fn into_bytes(self) -> Box<[u8]> {
        self.bytes
    }
}

/// In-memory backend failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MockIoError {
    /// A packet exceeds the configured maximum.
    PacketTooLarge {
        /// Packet byte length.
        length: usize,
        /// Configured maximum byte length.
        maximum: usize,
    },
    /// The caller-provided receive buffer cannot hold the queued packet.
    OutputTooSmall {
        /// Queued packet byte length.
        required: usize,
        /// Receive buffer byte length.
        available: usize,
    },
}

impl fmt::Display for MockIoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::PacketTooLarge { length, maximum } => {
                write!(
                    formatter,
                    "packet length {length} exceeds maximum {maximum}"
                )
            }
            Self::OutputTooSmall {
                required,
                available,
            } => write!(
                formatter,
                "receive buffer length {available} is smaller than queued packet {required}"
            ),
        }
    }
}

impl std::error::Error for MockIoError {}

/// Deterministic FIFO packet backend.
///
/// This backend intentionally allocates because it is for unit tests,
/// simulation, and differential testing. Production packet paths implement
/// [`PacketIo`] over preallocated driver-owned buffers.
#[derive(Debug)]
pub struct MockIo {
    maximum: usize,
    receive_queue: VecDeque<Frame>,
    transmit_queue: VecDeque<Frame>,
}

impl MockIo {
    /// Create an empty backend with a maximum complete IPv4 packet length.
    #[must_use]
    pub fn new(maximum: usize) -> Self {
        Self {
            maximum,
            receive_queue: VecDeque::new(),
            transmit_queue: VecDeque::new(),
        }
    }

    /// Queue one packet for the next receive operation.
    pub fn inject_receive(&mut self, packet: &[u8]) -> Result<(), MockIoError> {
        self.validate_length(packet.len())?;
        self.receive_queue.push_back(Frame::copy_from_slice(packet));
        Ok(())
    }

    /// Remove the oldest packet transmitted by the transport.
    pub fn pop_transmitted(&mut self) -> Option<Frame> {
        self.transmit_queue.pop_front()
    }

    /// Return the number of packets waiting to be received.
    #[must_use]
    pub fn pending_receive(&self) -> usize {
        self.receive_queue.len()
    }

    /// Return the number of captured transmitted packets.
    #[must_use]
    pub fn pending_transmit(&self) -> usize {
        self.transmit_queue.len()
    }

    fn validate_length(&self, length: usize) -> Result<(), MockIoError> {
        if length > self.maximum {
            Err(MockIoError::PacketTooLarge {
                length,
                maximum: self.maximum,
            })
        } else {
            Ok(())
        }
    }
}

impl PacketIo for MockIo {
    type Error = MockIoError;

    fn max_ipv4_packet(&self) -> usize {
        self.maximum
    }

    fn transmit_ipv4(&mut self, packet: &[u8]) -> Result<(), Self::Error> {
        self.validate_length(packet.len())?;
        self.transmit_queue
            .push_back(Frame::copy_from_slice(packet));
        Ok(())
    }

    fn receive_ipv4(&mut self, output: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        let Some(frame) = self.receive_queue.front() else {
            return Ok(None);
        };
        if output.len() < frame.len() {
            return Err(MockIoError::OutputTooSmall {
                required: frame.len(),
                available: output.len(),
            });
        }

        let length = frame.len();
        output[..length].copy_from_slice(frame.as_bytes());
        let removed = self.receive_queue.pop_front();
        debug_assert!(removed.is_some());
        Ok(Some(length))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_fifo_packets_in_both_directions() {
        let mut io = MockIo::new(64);
        io.inject_receive(&[1, 2]).unwrap();
        io.inject_receive(&[3]).unwrap();

        let mut output = [0_u8; 64];
        assert_eq!(io.receive_ipv4(&mut output).unwrap(), Some(2));
        assert_eq!(&output[..2], &[1, 2]);
        assert_eq!(io.receive_ipv4(&mut output).unwrap(), Some(1));
        assert_eq!(output[0], 3);
        assert_eq!(io.receive_ipv4(&mut output).unwrap(), None);

        io.transmit_ipv4(&[4, 5]).unwrap();
        assert_eq!(io.pop_transmitted().unwrap().as_bytes(), &[4, 5]);
    }

    #[test]
    fn short_receive_buffer_does_not_drop_frame() {
        let mut io = MockIo::new(64);
        io.inject_receive(&[1, 2, 3]).unwrap();

        assert_eq!(
            io.receive_ipv4(&mut [0_u8; 2]),
            Err(MockIoError::OutputTooSmall {
                required: 3,
                available: 2,
            })
        );
        assert_eq!(io.pending_receive(), 1);
    }

    #[test]
    fn enforces_configured_maximum() {
        let mut io = MockIo::new(2);
        assert!(matches!(
            io.inject_receive(&[1, 2, 3]),
            Err(MockIoError::PacketTooLarge { .. })
        ));
        assert!(matches!(
            io.transmit_ipv4(&[1, 2, 3]),
            Err(MockIoError::PacketTooLarge { .. })
        ));
    }
}
