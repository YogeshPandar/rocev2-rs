//! Work-request and completion descriptors.

/// One local scatter/gather element.
///
/// The initial transport supports one SGE per work request. The descriptor is
/// intentionally pointer-free; the memory crate resolves `address` and `lkey`
/// only after permission and range validation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Sge {
    /// Application virtual address.
    pub address: u64,
    /// Byte length.
    pub length: u32,
    /// Local memory key.
    pub lkey: u32,
}

impl Sge {
    /// Create a scatter/gather element.
    #[must_use]
    pub const fn new(address: u64, length: u32, lkey: u32) -> Self {
        Self {
            address,
            length,
            lkey,
        }
    }

    /// Return the exclusive end address, or `None` on integer overflow.
    #[must_use]
    pub fn checked_end(self) -> Option<u64> {
        self.address.checked_add(u64::from(self.length))
    }
}

/// Operation posted to an RC send queue.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum WorkRequestKind {
    /// Two-sided SEND.
    Send,
    /// One-sided RDMA WRITE.
    RdmaWrite {
        /// First remote virtual address.
        remote_address: u64,
        /// Remote memory key.
        rkey: u32,
    },
    /// One-sided RDMA READ.
    RdmaRead {
        /// First remote virtual address.
        remote_address: u64,
        /// Remote memory key.
        rkey: u32,
    },
}

/// Send-queue work request.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct WorkRequest {
    /// Caller-defined identifier returned in the completion.
    pub id: u64,
    /// Operation and remote addressing mode.
    pub kind: WorkRequestKind,
    /// Local scatter/gather element.
    pub sge: Sge,
    /// Whether successful completion should be reported.
    pub signaled: bool,
}

impl WorkRequest {
    /// Create a SEND work request.
    #[must_use]
    pub const fn send(id: u64, sge: Sge, signaled: bool) -> Self {
        Self {
            id,
            kind: WorkRequestKind::Send,
            sge,
            signaled,
        }
    }

    /// Create an RDMA WRITE work request.
    #[must_use]
    pub const fn write(
        id: u64,
        sge: Sge,
        remote_address: u64,
        rkey: u32,
        signaled: bool,
    ) -> Self {
        Self {
            id,
            kind: WorkRequestKind::RdmaWrite {
                remote_address,
                rkey,
            },
            sge,
            signaled,
        }
    }

    /// Create an RDMA READ work request.
    #[must_use]
    pub const fn read(
        id: u64,
        sge: Sge,
        remote_address: u64,
        rkey: u32,
        signaled: bool,
    ) -> Self {
        Self {
            id,
            kind: WorkRequestKind::RdmaRead {
                remote_address,
                rkey,
            },
            sge,
            signaled,
        }
    }
}

/// Receive-queue work request for a two-sided SEND.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RecvWorkRequest {
    /// Caller-defined identifier returned in the receive completion.
    pub id: u64,
    /// Local destination scatter/gather element.
    pub sge: Sge,
}

impl RecvWorkRequest {
    /// Create a receive work request.
    #[must_use]
    pub const fn new(id: u64, sge: Sge) -> Self {
        Self { id, sge }
    }
}

/// Completion operation category.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CompletionOpcode {
    /// SEND completion.
    Send,
    /// RDMA WRITE completion.
    RdmaWrite,
    /// RDMA READ completion.
    RdmaRead,
    /// Receive completion generated for an incoming SEND.
    Receive,
}

/// Completion status.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CompletionStatus {
    /// Operation completed successfully.
    Success,
    /// Local SGE was too short for the operation.
    LocalLengthError,
    /// Local key or access permission validation failed.
    LocalProtectionError,
    /// Peer reported a remote access error.
    RemoteAccessError,
    /// Peer reported an invalid request.
    RemoteInvalidRequest,
    /// Transport retry budget was exhausted.
    RetryExceeded,
    /// Receiver-not-ready retry budget was exhausted.
    RnrRetryExceeded,
    /// Packet or queue-pair state violated the transport protocol.
    TransportError,
    /// Work request was flushed because the QP entered error.
    Flushed,
}

/// Completion queue entry.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Completion {
    /// Work-request identifier supplied by the caller.
    pub work_request_id: u64,
    /// Operation category.
    pub opcode: CompletionOpcode,
    /// Final status.
    pub status: CompletionStatus,
    /// Number of bytes transferred for successful work.
    pub byte_len: u32,
}

impl Completion {
    /// Create a successful completion.
    #[must_use]
    pub const fn success(
        work_request_id: u64,
        opcode: CompletionOpcode,
        byte_len: u32,
    ) -> Self {
        Self {
            work_request_id,
            opcode,
            status: CompletionStatus::Success,
            byte_len,
        }
    }

    /// Create a failed completion with a zero transferred-byte count.
    #[must_use]
    pub const fn failure(
        work_request_id: u64,
        opcode: CompletionOpcode,
        status: CompletionStatus,
    ) -> Self {
        Self {
            work_request_id,
            opcode,
            status,
            byte_len: 0,
        }
    }

    /// Return whether the completion represents success.
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self.status, CompletionStatus::Success)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_sge_address_overflow() {
        let valid = Sge::new(10, 5, 7);
        assert_eq!(valid.checked_end(), Some(15));

        let overflow = Sge::new(u64::MAX, 1, 7);
        assert_eq!(overflow.checked_end(), None);
    }

    #[test]
    fn constructors_preserve_operation_metadata() {
        let sge = Sge::new(0x1000, 64, 9);
        let write = WorkRequest::write(4, sge, 0x2000, 11, true);
        assert_eq!(
            write.kind,
            WorkRequestKind::RdmaWrite {
                remote_address: 0x2000,
                rkey: 11,
            }
        );

        let completion = Completion::success(4, CompletionOpcode::RdmaWrite, 64);
        assert!(completion.is_success());
        assert_eq!(completion.byte_len, 64);
    }
}
