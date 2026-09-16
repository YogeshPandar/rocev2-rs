//! Pure-Rust userspace RoCEv2 Reliable Connected transport.
//!
//! The public crate composes four independently testable layers:
//!
//! - [`rocev2_wire`] for strict, allocation-free wire parsing and ICRC;
//! - [`rocev2_core`] for deterministic RC sequence/retry/QP state machines;
//! - [`rocev2_memory`] for checked local-key and remote-key access;
//! - [`rocev2_io`] for packet backends.
//!
//! The data path does not call libibverbs, librdmacm, UCX, or rdma-core.
//! Connection metadata is deliberately out of band in this first release.

#![forbid(unsafe_code)]

mod endpoint;
mod error;
mod packet;
mod qp;

pub use endpoint::{Endpoint, EndpointConfig, EndpointStats, PollProgress};
pub use error::{ApiError, PollError};
pub use packet::{DecodedPacket, Ipv4Path, decode_ipv4_packet, encode_ipv4_packet};
pub use qp::QpHandle;

pub use rocev2_core as core;
pub use rocev2_io as io;
pub use rocev2_memory as memory;
pub use rocev2_wire as wire;

pub use rocev2_core::{
    Completion, CompletionOpcode, CompletionStatus, PathMtu, Psn, QpConfig, QpState,
    RecvWorkRequest, Sge, WorkRequest, WorkRequestKind,
};
pub use rocev2_memory::{Access, MemoryRegion};
