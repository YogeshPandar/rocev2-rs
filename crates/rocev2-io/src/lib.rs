//! packet i/o abstractions for the `RoCEv2` data plane.
//!
//! the scalar trait exchanges complete ipv4 packets in caller-owned buffers.
//! the batch trait adds explicit receive and transmit frame ownership so
//! `AF_XDP` can expose UMEM frames without transport copies.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[allow(unsafe_code)]
#[cfg(all(feature = "afxdp", target_os = "linux"))]
mod afxdp;
mod ethernet;
mod fixed;
#[cfg(feature = "std")]
mod mock;

#[allow(unsafe_code)]
#[cfg(all(feature = "raw-ipv4", target_os = "linux"))]
mod raw_ipv4;

#[cfg(all(feature = "afxdp", target_os = "linux"))]
pub use afxdp::{
    AfxdpBindMode, AfxdpConfig, AfxdpError, AfxdpKernelStatistics, AfxdpRxFrame, AfxdpSocket,
    AfxdpStatistics, AfxdpTxFrame, UmemBacking,
};
pub use ethernet::{ETHERNET_HEADER_LEN, EthernetPath};
pub use fixed::{FixedFrame, FixedPacketIo, FixedPacketIoError, FixedRxFrame, FixedTxFrame};
#[cfg(feature = "std")]
pub use mock::{Frame, MockIo, MockIoError};
#[cfg(all(feature = "raw-ipv4", target_os = "linux"))]
pub use raw_ipv4::{RawIpv4Config, RawIpv4Socket};

/// nonblocking complete-ipv4-packet i/o.
pub trait PacketIo {
    /// backend-specific error.
    type Error: core::error::Error + Send + Sync + 'static;

    /// maximum complete ipv4 packet accepted by this backend.
    #[must_use]
    fn max_ipv4_packet(&self) -> usize;

    /// transmit one complete ipv4 packet, starting at version and ihl.
    fn transmit_ipv4(&mut self, packet: &[u8]) -> Result<(), Self::Error>;

    /// receive one complete ipv4 packet into `output`.
    ///
    /// returns `Ok(None)` when a nonblocking backend has no packet ready.
    fn receive_ipv4(&mut self, output: &mut [u8]) -> Result<Option<usize>, Self::Error>;
}

/// one frame prepared for batch transmit.
///
/// a frame remains caller-owned while [`Self::frame`] is `Some`. a successful
/// [`PacketBatchIo::submit_tx_batch`] consumes the accepted prefix by taking
/// the frame from each accepted packet.
#[derive(Debug)]
pub struct TxPacket<F> {
    frame: Option<F>,
    length: usize,
}

impl<F> TxPacket<F> {
    /// create an empty staging slot.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            frame: None,
            length: 0,
        }
    }

    /// create one caller-owned transmit packet.
    #[must_use]
    pub const fn new(frame: F, length: usize) -> Self {
        Self {
            frame: Some(frame),
            length,
        }
    }

    /// return the packet byte length.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.length
    }

    /// return whether the packet length is zero.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// borrow the caller-owned frame when it has not been submitted.
    #[must_use]
    pub const fn frame(&self) -> Option<&F> {
        self.frame.as_ref()
    }

    /// mutably borrow the caller-owned frame when it has not been submitted.
    #[must_use]
    pub fn frame_mut(&mut self) -> Option<&mut F> {
        self.frame.as_mut()
    }

    /// replace this staging slot with one caller-owned transmit packet.
    pub fn set(&mut self, frame: F, length: usize) {
        self.frame = Some(frame);
        self.length = length;
    }

    /// take ownership of the frame.
    ///
    /// packet backends use this for the accepted prefix during submission.
    pub fn take_frame(&mut self) -> Option<F> {
        self.frame.take()
    }

    /// recover an unsubmitted frame.
    pub fn into_frame(self) -> Option<F> {
        self.frame
    }
}

/// transmit submission failure after a possibly accepted packet prefix.
#[derive(Debug)]
pub struct SubmitError<E> {
    submitted: usize,
    error: E,
}

impl<E> SubmitError<E> {
    /// create a submission error with its accepted prefix length.
    #[must_use]
    pub const fn new(submitted: usize, error: E) -> Self {
        Self { submitted, error }
    }

    /// return the number of packets whose ownership moved to the backend.
    #[must_use]
    pub const fn submitted(&self) -> usize {
        self.submitted
    }

    /// borrow the backend error.
    #[must_use]
    pub const fn error(&self) -> &E {
        &self.error
    }

    /// recover the backend error.
    pub fn into_error(self) -> E {
        self.error
    }
}

impl<E: core::fmt::Display> core::fmt::Display for SubmitError<E> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "packet submission failed after {} packets: {}",
            self.submitted, self.error
        )
    }
}

impl<E> core::error::Error for SubmitError<E>
where
    E: core::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// nonblocking batch packet i/o with explicit frame ownership.
///
/// receive frames are owned by the caller after `receive_batch` and until
/// `recycle_rx_batch`. transmit frames are owned by the caller after
/// `acquire_tx_batch`; accepted submissions transfer ownership to the backend
/// until `reap_tx_completions` returns those frames to its free pool.
///
/// methods that return `Err` without a submitted-prefix count must leave frame
/// ownership unchanged. backpressure is represented by `Ok(0)` or a short
/// successful prefix, not by an error.
pub trait PacketBatchIo: PacketIo {
    /// backend receive-frame handle.
    type RxFrame;
    /// backend transmit-frame handle.
    type TxFrame;

    /// dequeue up to `frames.len()` received ipv4 frames.
    ///
    /// the backend writes `Some(frame)` to the first returned-count slots.
    fn receive_batch(&mut self, frames: &mut [Option<Self::RxFrame>])
    -> Result<usize, Self::Error>;

    /// borrow the complete ipv4 packet referenced by one receive frame.
    fn rx_ipv4<'a>(&'a self, frame: &Self::RxFrame) -> Result<&'a [u8], Self::Error>;

    /// return caller-owned receive frames to the backend.
    ///
    /// every `Some` slot must be consumed and replaced with `None` on success.
    fn recycle_rx_batch(&mut self, frames: &mut [Option<Self::RxFrame>])
    -> Result<(), Self::Error>;

    /// acquire up to `frames.len()` writable transmit frames.
    ///
    /// the backend writes `Some(frame)` to the first returned-count slots.
    fn acquire_tx_batch(
        &mut self,
        frames: &mut [Option<Self::TxFrame>],
    ) -> Result<usize, Self::Error>;

    /// borrow writable storage for one caller-owned transmit frame.
    fn tx_ipv4_buffer<'a>(&'a mut self, frame: &Self::TxFrame)
    -> Result<&'a mut [u8], Self::Error>;

    /// submit a prefix of prepared transmit packets.
    ///
    /// accepted packets must have their frame taken from the corresponding
    /// `TxPacket`. an error reports the accepted prefix in [`SubmitError`].
    fn submit_tx_batch(
        &mut self,
        packets: &mut [TxPacket<Self::TxFrame>],
    ) -> Result<usize, SubmitError<Self::Error>>;

    /// return unsubmitted caller-owned transmit frames to the backend.
    ///
    /// every `Some` slot must be consumed and replaced with `None` on success.
    fn release_tx_batch(&mut self, frames: &mut [Option<Self::TxFrame>])
    -> Result<(), Self::Error>;

    /// reclaim up to `budget` completed transmit frames into the backend pool.
    fn reap_tx_completions(&mut self, budget: usize) -> Result<usize, Self::Error>;
}
