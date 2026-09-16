//! RoCEv2 wire-format support.
//!
//! This crate is dependency-free and `no_std`. It parses and encodes the
//! InfiniBand transport headers carried by a RoCEv2 UDP datagram, and computes
//! the invariant CRC (ICRC) used by RoCE.
//!
//! The parser never dereferences packet-provided addresses and never allocates.

#![no_std]
#![forbid(unsafe_code)]

mod aeth;
mod bth;
mod error;
mod icrc;
mod ipv4;
mod opcode;
mod packet;
mod reth;

pub use aeth::{Aeth, AethClass, NakCode};
pub use bth::Bth;
pub use error::WireError;
pub use icrc::{ICRC_LEN, ICRC_SEED, Icrc};
pub use ipv4::{IP_PROTOCOL_UDP, IPV4_HEADER_LEN, Ipv4Header, UDP_HEADER_LEN, UdpHeader};
pub use opcode::{Opcode, Operation, SegmentPosition};
pub use packet::{PacketRef, PacketSpec, ParseOptions};
pub use reth::Reth;

/// IANA-assigned RoCEv2 UDP destination port.
pub const ROCE_V2_UDP_PORT: u16 = 4791;

/// Base Transport Header length in bytes.
pub const BTH_LEN: usize = 12;

/// RDMA Extended Transport Header length in bytes.
pub const RETH_LEN: usize = 16;

/// ACK Extended Transport Header length in bytes.
pub const AETH_LEN: usize = 4;

/// Width of a packet sequence number.
pub const PSN_BITS: u32 = 24;

/// Mask for the 24-bit packet sequence number field.
pub const PSN_MASK: u32 = 0x00ff_ffff;

/// Mask for the 24-bit queue-pair number field.
pub const QPN_MASK: u32 = 0x00ff_ffff;
