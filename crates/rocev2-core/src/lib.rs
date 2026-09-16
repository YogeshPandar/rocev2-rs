//! Allocation-free Reliable Connected transport primitives.
//!
//! The crate contains only deterministic state machines and fixed-capacity
//! queues. Time and packet I/O are supplied by the caller, making the code
//! suitable for `no_std`, polling data planes, simulation, and fuzzing.

#![no_std]
#![forbid(unsafe_code)]

mod ack;
mod psn;
mod qp;
mod retry;
mod ring;
mod segment;
mod work;

pub use ack::{AckAdvance, ReceiveDisposition, ReceivePsn, SendWindow};
pub use psn::{Psn, PsnOrdering};
pub use qp::{PathMtu, QpConfig, QpState, QpStateMachine, StateTransitionError};
pub use retry::{
    RetryBudget, RetryDecision, RetryPolicy, RetryReason, Timer, rnr_timer_microseconds,
    rnr_timer_ticks,
};
pub use ring::{PushError, Ring};
pub use segment::{Segment, SegmentError, Segmenter, TransferKind};
pub use work::{
    Completion, CompletionOpcode, CompletionStatus, RecvWorkRequest, Sge, WorkRequest, WorkRequestKind,
};
