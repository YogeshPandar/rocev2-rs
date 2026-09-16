//! allocation-free fixed packet backend for deterministic testing.

use crate::{PacketBatchIo, PacketIo, SubmitError, TxPacket};
use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RxState {
    Free,
    Queued,
    AppOwned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TxState {
    Free,
    AppOwned,
    InFlight,
}

/// one fixed-capacity captured packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedFrame<const MTU: usize> {
    bytes: [u8; MTU],
    length: usize,
}

impl<const MTU: usize> FixedFrame<MTU> {
    const EMPTY: Self = Self {
        bytes: [0; MTU],
        length: 0,
    };

    fn copy_from_slice(bytes: &[u8]) -> Self {
        let mut frame = Self::EMPTY;
        frame.bytes[..bytes.len()].copy_from_slice(bytes);
        frame.length = bytes.len();
        frame
    }

    /// return the packet bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }

    /// return the packet length.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.length
    }

    /// return whether the packet is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }
}

/// generation-checked fixed receive-frame handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedRxFrame {
    index: usize,
    generation: u32,
}

/// generation-checked fixed transmit-frame handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedTxFrame {
    index: usize,
    generation: u32,
}

/// fixed backend failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixedPacketIoError {
    /// a packet exceeds the compile-time packet size.
    PacketTooLarge {
        /// packet byte length.
        length: usize,
        /// backend packet limit.
        maximum: usize,
    },
    /// a scalar receive buffer cannot hold the queued packet.
    OutputTooSmall {
        /// queued packet byte length.
        required: usize,
        /// receive buffer byte length.
        available: usize,
    },
    /// no fixed receive slot can accept another injected packet.
    ReceiveQueueFull,
    /// no fixed capture slot can retain another transmitted packet.
    TransmitQueueFull,
    /// a batch output slot was already occupied by the caller.
    OutputSlotOccupied,
    /// a receive frame is stale, duplicated, or not caller-owned.
    InvalidReceiveFrame,
    /// a transmit frame is stale, duplicated, or not caller-owned.
    InvalidTransmitFrame,
}

impl fmt::Display for FixedPacketIoError {
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
            Self::ReceiveQueueFull => formatter.write_str("fixed receive queue is full"),
            Self::TransmitQueueFull => formatter.write_str("fixed transmit capture queue is full"),
            Self::OutputSlotOccupied => {
                formatter.write_str("batch output slot is already occupied")
            }
            Self::InvalidReceiveFrame => formatter.write_str("invalid fixed receive frame"),
            Self::InvalidTransmitFrame => formatter.write_str("invalid fixed transmit frame"),
        }
    }
}

impl std::error::Error for FixedPacketIoError {}

#[derive(Debug)]
struct IndexRing<const N: usize> {
    entries: [usize; N],
    head: usize,
    tail: usize,
    len: usize,
}

impl<const N: usize> IndexRing<N> {
    const fn new() -> Self {
        Self {
            entries: [0; N],
            head: 0,
            tail: 0,
            len: 0,
        }
    }

    const fn len(&self) -> usize {
        self.len
    }

    fn push(&mut self, value: usize) -> bool {
        if self.len == N {
            return false;
        }
        if N == 0 {
            return false;
        }
        self.entries[self.tail] = value;
        self.tail = (self.tail + 1) % N;
        self.len += 1;
        true
    }

    fn front(&self) -> Option<usize> {
        (self.len != 0).then(|| self.entries[self.head])
    }

    fn pop(&mut self) -> Option<usize> {
        let value = self.front()?;
        self.head = (self.head + 1) % N;
        self.len -= 1;
        Some(value)
    }
}

#[derive(Debug)]
struct FrameRing<const N: usize, const MTU: usize> {
    entries: [FixedFrame<MTU>; N],
    head: usize,
    tail: usize,
    len: usize,
}

impl<const N: usize, const MTU: usize> FrameRing<N, MTU> {
    const fn new() -> Self {
        Self {
            entries: [FixedFrame::EMPTY; N],
            head: 0,
            tail: 0,
            len: 0,
        }
    }

    const fn len(&self) -> usize {
        self.len
    }

    const fn remaining_capacity(&self) -> usize {
        N - self.len
    }

    fn push(&mut self, frame: FixedFrame<MTU>) -> bool {
        if self.len == N || N == 0 {
            return false;
        }
        self.entries[self.tail] = frame;
        self.tail = (self.tail + 1) % N;
        self.len += 1;
        true
    }

    fn pop(&mut self) -> Option<FixedFrame<MTU>> {
        if self.len == 0 {
            return None;
        }
        let frame = self.entries[self.head];
        self.head = (self.head + 1) % N;
        self.len -= 1;
        Some(frame)
    }
}

/// fixed receive and transmit storage with no heap allocation.
///
/// the backend models the ownership transitions needed by `AF_XDP`: receive
/// frames move from backend ownership to application ownership and back;
/// transmit frames move from the free pool to the application, then in-flight,
/// then back to the free pool when completions are reaped.
#[derive(Debug)]
pub struct FixedPacketIo<const RX: usize, const TX: usize, const MTU: usize> {
    rx_bytes: [[u8; MTU]; RX],
    rx_lengths: [usize; RX],
    rx_states: [RxState; RX],
    rx_generations: [u32; RX],
    rx_free: IndexRing<RX>,
    rx_ready: IndexRing<RX>,
    tx_bytes: [[u8; MTU]; TX],
    tx_states: [TxState; TX],
    tx_generations: [u32; TX],
    tx_free: IndexRing<TX>,
    tx_completions: IndexRing<TX>,
    transmitted: FrameRing<TX, MTU>,
}

impl<const RX: usize, const TX: usize, const MTU: usize> FixedPacketIo<RX, TX, MTU> {
    /// create an empty fixed backend.
    #[must_use]
    pub fn new() -> Self {
        let mut backend = Self {
            rx_bytes: [[0; MTU]; RX],
            rx_lengths: [0; RX],
            rx_states: [RxState::Free; RX],
            rx_generations: [0; RX],
            rx_free: IndexRing::new(),
            rx_ready: IndexRing::new(),
            tx_bytes: [[0; MTU]; TX],
            tx_states: [TxState::Free; TX],
            tx_generations: [0; TX],
            tx_free: IndexRing::new(),
            tx_completions: IndexRing::new(),
            transmitted: FrameRing::new(),
        };
        for index in 0..RX {
            let inserted = backend.rx_free.push(index);
            debug_assert!(inserted);
        }
        for index in 0..TX {
            let inserted = backend.tx_free.push(index);
            debug_assert!(inserted);
        }
        backend
    }

    /// inject one packet for a future receive operation.
    pub fn inject_receive(&mut self, packet: &[u8]) -> Result<(), FixedPacketIoError> {
        Self::validate_length(packet.len())?;
        let Some(index) = self.rx_free.pop() else {
            return Err(FixedPacketIoError::ReceiveQueueFull);
        };
        debug_assert_eq!(self.rx_states[index], RxState::Free);
        self.rx_bytes[index][..packet.len()].copy_from_slice(packet);
        self.rx_lengths[index] = packet.len();
        self.rx_states[index] = RxState::Queued;
        let inserted = self.rx_ready.push(index);
        debug_assert!(inserted);
        Ok(())
    }

    /// remove the oldest captured transmit packet.
    pub fn pop_transmitted(&mut self) -> Option<FixedFrame<MTU>> {
        self.transmitted.pop()
    }

    /// return the number of packets waiting for receive ownership.
    #[must_use]
    pub const fn pending_receive(&self) -> usize {
        self.rx_ready.len()
    }

    /// return the number of captured transmit packets.
    #[must_use]
    pub const fn pending_transmit(&self) -> usize {
        self.transmitted.len()
    }

    /// return the number of in-flight transmit completions.
    #[must_use]
    pub const fn pending_tx_completions(&self) -> usize {
        self.tx_completions.len()
    }

    fn validate_length(length: usize) -> Result<(), FixedPacketIoError> {
        if length > MTU {
            Err(FixedPacketIoError::PacketTooLarge {
                length,
                maximum: MTU,
            })
        } else {
            Ok(())
        }
    }

    fn valid_rx_frame(&self, frame: FixedRxFrame) -> bool {
        self.rx_states.get(frame.index) == Some(&RxState::AppOwned)
            && self.rx_generations.get(frame.index) == Some(&frame.generation)
    }

    fn valid_tx_frame(&self, frame: FixedTxFrame) -> bool {
        self.tx_states.get(frame.index) == Some(&TxState::AppOwned)
            && self.tx_generations.get(frame.index) == Some(&frame.generation)
    }
}

impl<const RX: usize, const TX: usize, const MTU: usize> Default for FixedPacketIo<RX, TX, MTU> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const RX: usize, const TX: usize, const MTU: usize> PacketIo for FixedPacketIo<RX, TX, MTU> {
    type Error = FixedPacketIoError;

    fn max_ipv4_packet(&self) -> usize {
        MTU
    }

    fn transmit_ipv4(&mut self, packet: &[u8]) -> Result<(), Self::Error> {
        Self::validate_length(packet.len())?;
        if self.transmitted.remaining_capacity() == 0 {
            return Err(FixedPacketIoError::TransmitQueueFull);
        }
        let inserted = self.transmitted.push(FixedFrame::copy_from_slice(packet));
        debug_assert!(inserted);
        Ok(())
    }

    fn receive_ipv4(&mut self, output: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        let Some(index) = self.rx_ready.front() else {
            return Ok(None);
        };
        let length = self.rx_lengths[index];
        if output.len() < length {
            return Err(FixedPacketIoError::OutputTooSmall {
                required: length,
                available: output.len(),
            });
        }
        output[..length].copy_from_slice(&self.rx_bytes[index][..length]);
        let removed = self.rx_ready.pop();
        debug_assert_eq!(removed, Some(index));
        self.rx_states[index] = RxState::Free;
        let returned = self.rx_free.push(index);
        debug_assert!(returned);
        Ok(Some(length))
    }
}

impl<const RX: usize, const TX: usize, const MTU: usize> PacketBatchIo
    for FixedPacketIo<RX, TX, MTU>
{
    type RxFrame = FixedRxFrame;
    type TxFrame = FixedTxFrame;

    fn receive_batch(
        &mut self,
        frames: &mut [Option<Self::RxFrame>],
    ) -> Result<usize, Self::Error> {
        if frames.iter().any(Option::is_some) {
            return Err(FixedPacketIoError::OutputSlotOccupied);
        }
        let mut received = 0;
        for slot in frames {
            let Some(index) = self.rx_ready.pop() else {
                break;
            };
            debug_assert_eq!(self.rx_states[index], RxState::Queued);
            self.rx_states[index] = RxState::AppOwned;
            self.rx_generations[index] = next_generation(self.rx_generations[index]);
            *slot = Some(FixedRxFrame {
                index,
                generation: self.rx_generations[index],
            });
            received += 1;
        }
        Ok(received)
    }

    fn rx_ipv4<'a>(&'a self, frame: &Self::RxFrame) -> Result<&'a [u8], Self::Error> {
        if !self.valid_rx_frame(*frame) {
            return Err(FixedPacketIoError::InvalidReceiveFrame);
        }
        let length = self.rx_lengths[frame.index];
        Ok(&self.rx_bytes[frame.index][..length])
    }

    fn recycle_rx_batch(
        &mut self,
        frames: &mut [Option<Self::RxFrame>],
    ) -> Result<(), Self::Error> {
        validate_unique_rx(self, frames)?;
        for slot in frames {
            let Some(frame) = slot.take() else {
                continue;
            };
            self.rx_states[frame.index] = RxState::Free;
            self.rx_lengths[frame.index] = 0;
            let returned = self.rx_free.push(frame.index);
            debug_assert!(returned);
        }
        Ok(())
    }

    fn acquire_tx_batch(
        &mut self,
        frames: &mut [Option<Self::TxFrame>],
    ) -> Result<usize, Self::Error> {
        if frames.iter().any(Option::is_some) {
            return Err(FixedPacketIoError::OutputSlotOccupied);
        }
        let mut acquired = 0;
        for slot in frames {
            let Some(index) = self.tx_free.pop() else {
                break;
            };
            debug_assert_eq!(self.tx_states[index], TxState::Free);
            self.tx_states[index] = TxState::AppOwned;
            self.tx_generations[index] = next_generation(self.tx_generations[index]);
            *slot = Some(FixedTxFrame {
                index,
                generation: self.tx_generations[index],
            });
            acquired += 1;
        }
        Ok(acquired)
    }

    fn tx_ipv4_buffer<'a>(
        &'a mut self,
        frame: &Self::TxFrame,
    ) -> Result<&'a mut [u8], Self::Error> {
        if !self.valid_tx_frame(*frame) {
            return Err(FixedPacketIoError::InvalidTransmitFrame);
        }
        Ok(&mut self.tx_bytes[frame.index])
    }

    fn submit_tx_batch(
        &mut self,
        packets: &mut [TxPacket<Self::TxFrame>],
    ) -> Result<usize, SubmitError<Self::Error>> {
        let accepted = packets.len().min(self.transmitted.remaining_capacity());
        for index in 0..accepted {
            let packet = &packets[index];
            let Some(frame) = packet.frame().copied() else {
                return Err(SubmitError::new(
                    0,
                    FixedPacketIoError::InvalidTransmitFrame,
                ));
            };
            if packet.len() > MTU || !self.valid_tx_frame(frame) {
                let error = if packet.len() > MTU {
                    FixedPacketIoError::PacketTooLarge {
                        length: packet.len(),
                        maximum: MTU,
                    }
                } else {
                    FixedPacketIoError::InvalidTransmitFrame
                };
                return Err(SubmitError::new(0, error));
            }
            for previous in &packets[..index] {
                if previous.frame().copied() == Some(frame) {
                    return Err(SubmitError::new(
                        0,
                        FixedPacketIoError::InvalidTransmitFrame,
                    ));
                }
            }
        }

        for (submitted, packet) in packets[..accepted].iter_mut().enumerate() {
            let Some(frame) = packet.take_frame() else {
                return Err(SubmitError::new(
                    submitted,
                    FixedPacketIoError::InvalidTransmitFrame,
                ));
            };
            let capture = FixedFrame::copy_from_slice(&self.tx_bytes[frame.index][..packet.len()]);
            let captured = self.transmitted.push(capture);
            debug_assert!(captured);
            self.tx_states[frame.index] = TxState::InFlight;
            let queued = self.tx_completions.push(frame.index);
            debug_assert!(queued);
        }
        Ok(accepted)
    }

    fn release_tx_batch(
        &mut self,
        frames: &mut [Option<Self::TxFrame>],
    ) -> Result<(), Self::Error> {
        validate_unique_tx(self, frames)?;
        for slot in frames {
            let Some(frame) = slot.take() else {
                continue;
            };
            self.tx_states[frame.index] = TxState::Free;
            let returned = self.tx_free.push(frame.index);
            debug_assert!(returned);
        }
        Ok(())
    }

    fn reap_tx_completions(&mut self, budget: usize) -> Result<usize, Self::Error> {
        let mut reaped = 0;
        while reaped < budget {
            let Some(index) = self.tx_completions.pop() else {
                break;
            };
            debug_assert_eq!(self.tx_states[index], TxState::InFlight);
            self.tx_states[index] = TxState::Free;
            let returned = self.tx_free.push(index);
            debug_assert!(returned);
            reaped += 1;
        }
        Ok(reaped)
    }
}

fn validate_unique_rx<const RX: usize, const TX: usize, const MTU: usize>(
    backend: &FixedPacketIo<RX, TX, MTU>,
    frames: &[Option<FixedRxFrame>],
) -> Result<(), FixedPacketIoError> {
    for (index, slot) in frames.iter().enumerate() {
        let Some(frame) = slot else {
            continue;
        };
        if !backend.valid_rx_frame(*frame) {
            return Err(FixedPacketIoError::InvalidReceiveFrame);
        }
        if frames[..index].iter().flatten().any(|other| other == frame) {
            return Err(FixedPacketIoError::InvalidReceiveFrame);
        }
    }
    Ok(())
}

fn validate_unique_tx<const RX: usize, const TX: usize, const MTU: usize>(
    backend: &FixedPacketIo<RX, TX, MTU>,
    frames: &[Option<FixedTxFrame>],
) -> Result<(), FixedPacketIoError> {
    for (index, slot) in frames.iter().enumerate() {
        let Some(frame) = slot else {
            continue;
        };
        if !backend.valid_tx_frame(*frame) {
            return Err(FixedPacketIoError::InvalidTransmitFrame);
        }
        if frames[..index].iter().flatten().any(|other| other == frame) {
            return Err(FixedPacketIoError::InvalidTransmitFrame);
        }
    }
    Ok(())
}

const fn next_generation(generation: u32) -> u32 {
    let next = generation.wrapping_add(1);
    if next == 0 { 1 } else { next }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_receive_preserves_short_packet() {
        let mut io = FixedPacketIo::<2, 2, 64>::new();
        io.inject_receive(&[1, 2, 3]).unwrap();
        assert_eq!(
            io.receive_ipv4(&mut [0; 2]),
            Err(FixedPacketIoError::OutputTooSmall {
                required: 3,
                available: 2,
            })
        );
        assert_eq!(io.pending_receive(), 1);
    }

    #[test]
    fn batch_receive_requires_recycle_before_slot_reuse() {
        let mut io = FixedPacketIo::<2, 2, 64>::new();
        io.inject_receive(&[1, 2, 3]).unwrap();
        io.inject_receive(&[4, 5]).unwrap();
        let mut frames = [None, None];
        assert_eq!(io.receive_batch(&mut frames).unwrap(), 2);
        assert_eq!(io.rx_ipv4(frames[0].as_ref().unwrap()).unwrap(), &[1, 2, 3]);
        assert_eq!(io.rx_ipv4(frames[1].as_ref().unwrap()).unwrap(), &[4, 5]);
        assert_eq!(
            io.inject_receive(&[6]),
            Err(FixedPacketIoError::ReceiveQueueFull)
        );
        io.recycle_rx_batch(&mut frames).unwrap();
        assert!(frames.iter().all(Option::is_none));
        io.inject_receive(&[6]).unwrap();
    }

    #[test]
    fn transmit_ownership_returns_only_after_completion_reap() {
        let mut io = FixedPacketIo::<1, 2, 64>::new();
        let mut frames = [None, None];
        assert_eq!(io.acquire_tx_batch(&mut frames).unwrap(), 2);
        for (index, frame) in frames.iter().flatten().enumerate() {
            io.tx_ipv4_buffer(frame).unwrap()[0] = index as u8 + 7;
        }
        let first = frames[0].take().unwrap();
        let second = frames[1].take().unwrap();
        let mut packets = [TxPacket::new(first, 1), TxPacket::new(second, 1)];
        assert_eq!(io.submit_tx_batch(&mut packets).unwrap(), 2);
        assert!(packets.iter().all(|packet| packet.frame().is_none()));
        assert_eq!(io.pending_tx_completions(), 2);
        assert_eq!(io.acquire_tx_batch(&mut frames).unwrap(), 0);
        assert_eq!(io.pop_transmitted().unwrap().as_bytes(), &[7]);
        assert_eq!(io.pop_transmitted().unwrap().as_bytes(), &[8]);
        assert_eq!(io.reap_tx_completions(1).unwrap(), 1);
        assert_eq!(io.acquire_tx_batch(&mut frames[..1]).unwrap(), 1);
        io.release_tx_batch(&mut frames).unwrap();
    }

    #[test]
    fn stale_and_duplicate_handles_are_rejected() {
        let mut io = FixedPacketIo::<1, 1, 64>::new();
        let mut frames = [None];
        assert_eq!(io.acquire_tx_batch(&mut frames).unwrap(), 1);
        let frame = frames[0].unwrap();
        let mut duplicated = [Some(frame), Some(frame)];
        assert_eq!(
            io.release_tx_batch(&mut duplicated),
            Err(FixedPacketIoError::InvalidTransmitFrame)
        );
        io.release_tx_batch(&mut frames).unwrap();
        assert!(matches!(
            io.tx_ipv4_buffer(&frame),
            Err(FixedPacketIoError::InvalidTransmitFrame)
        ));
    }
}
