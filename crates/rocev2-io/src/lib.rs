//! Packet I/O abstractions for the `RoCEv2` data plane.
//!
//! The central trait exchanges complete IPv4 packets in caller-owned buffers.
//! This keeps transport parsing independent from Linux syscalls and permits an
//! `AF_XDP` backend to prepend or strip Ethernet without changing RC logic.

#![deny(unsafe_op_in_unsafe_fn)]

mod mock;

#[allow(unsafe_code)]
#[cfg(all(feature = "raw-ipv4", target_os = "linux"))]
mod raw_ipv4;

pub use mock::{Frame, MockIo, MockIoError};
#[cfg(all(feature = "raw-ipv4", target_os = "linux"))]
pub use raw_ipv4::{RawIpv4Config, RawIpv4Socket};

/// Nonblocking complete-IPv4-packet I/O.
pub trait PacketIo {
    /// Backend-specific error.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Maximum complete IPv4 packet accepted by this backend.
    #[must_use]
    fn max_ipv4_packet(&self) -> usize;

    /// Transmit one complete IPv4 packet, starting at version and IHL.
    fn transmit_ipv4(&mut self, packet: &[u8]) -> Result<(), Self::Error>;

    /// Receive one complete IPv4 packet into `output`.
    ///
    /// Returns `Ok(None)` when a nonblocking backend has no packet ready.
    fn receive_ipv4(&mut self, output: &mut [u8]) -> Result<Option<usize>, Self::Error>;
}
