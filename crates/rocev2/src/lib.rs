//! Pure-Rust userspace `RoCEv2` Reliable Connected transport foundations.
//!
//! The public crate composes four independently testable layers:
//!
//! - [`rocev2_wire`] for strict, allocation-free wire parsing and ICRC;
//! - [`rocev2_core`] for deterministic RC sequence, retry, and QP state machines;
//! - [`rocev2_memory`] for checked local-key and remote-key access;
//! - [`rocev2_io`] for complete-packet backends.
//!
//! The data path does not call libibverbs, librdmacm, UCX, or rdma-core.
//! Connection metadata is deliberately out of band in this first release.
//!
//! [`RcEndpoint`] adds fixed-capacity posted SEND, RDMA WRITE, and RDMA READ
//! execution with completions, segmentation, ACK/NAK/RNR handling, and retry
//! scheduling. Linux RXE and hardware interoperability remain explicit
//! pre-1.0 qualification gates.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

mod connection;
mod endpoint;
mod error;
#[cfg(all(target_os = "linux", any(feature = "raw-ipv4", feature = "afxdp")))]
mod keys;
mod packet;
mod qp;
mod rc;
#[cfg(all(target_os = "linux", any(feature = "raw-ipv4", feature = "afxdp")))]
pub use keys::SystemKeyGenerator;

pub use connection::{ConnectionInfoError, RC_CONNECTION_INFO_LEN, RcConnectionInfo};
pub use endpoint::{Endpoint, EndpointConfig, EndpointStats, PollProgress};
pub use error::{ApiError, PollError, QueueKind};
pub use packet::{
    DecodedPacket, Ipv4Path, MIN_ROCE_IPV4_PACKET, decode_ipv4_packet, encode_ipv4_packet,
};
pub use qp::QpHandle;
pub use rc::{
    MAX_BATCH_PACKETS, RcEndpoint, RcEndpointConfig, RcEndpointStats, RcProgress, RcQpConfig,
};

pub use rocev2_core as core;
pub use rocev2_io as io;
pub use rocev2_memory as memory;
pub use rocev2_wire as wire;

pub use rocev2_core::{
    Completion, CompletionOpcode, CompletionStatus, PathMtu, Psn, QpConfig, QpState,
    RecvWorkRequest, Sge, WorkRequest, WorkRequestKind,
};
pub use rocev2_memory::{
    AccessFlags, KeyGenerator, MemoryAccess, MemoryError, MemoryRegistry, RegionHandle,
    RegionLease, RemoteMemory,
};

/// Compatibility name for registered-memory access rights.
pub type Access = AccessFlags;

/// Compatibility name for a registered-memory region handle.
pub type MemoryRegion = RegionHandle;
