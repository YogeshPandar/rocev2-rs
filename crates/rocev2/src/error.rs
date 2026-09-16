//! Public API error types.

use core::fmt;
use rocev2_core::StateTransitionError;
use rocev2_memory::MemoryError;
use rocev2_wire::WireError;

/// Fixed-capacity queue that rejected a post operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueKind {
    /// Queue-pair send queue.
    Send,
    /// Queue-pair receive queue.
    Receive,
    /// Queue-pair completion queue or its reservation pool.
    Completion,
}

/// Configuration, packet, memory, or queue-pair error returned by the public API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ApiError {
    /// A wire object could not be decoded or encoded.
    Wire(WireError),
    /// A caller-owned packet buffer is shorter than required.
    BufferTooShort {
        /// Minimum required byte length.
        needed: usize,
        /// Supplied byte length.
        actual: usize,
    },
    /// A packet is larger than the configured endpoint limit.
    PacketTooLarge {
        /// Packet byte length.
        length: usize,
        /// Configured maximum byte length.
        maximum: usize,
    },
    /// The endpoint maximum cannot be supported by the selected backend.
    UnsupportedMaximumPacket {
        /// Requested endpoint maximum.
        requested: usize,
        /// Backend maximum.
        backend: usize,
    },
    /// The IPv4 protocol field was not UDP.
    InvalidIpv4Protocol(u8),
    /// IPv4 fragmentation is not supported by the v1 data path.
    FragmentedIpv4,
    /// The UDP destination port was not the `RoCEv2` port.
    InvalidRoceDestinationPort(u16),
    /// A UDP length field was invalid or inconsistent with IPv4.
    InvalidUdpLength {
        /// Length declared by UDP.
        declared: usize,
        /// UDP bytes carried by IPv4.
        actual: usize,
    },
    /// Checked packet-length arithmetic overflowed.
    ArithmeticOverflow,
    /// The fixed-capacity queue-pair table is full.
    QpTableFull,
    /// A queue-pair handle is unknown, stale, or out of range.
    InvalidQpHandle,
    /// A local queue-pair number is already registered.
    DuplicateLocalQpn(u32),
    /// No queue pair owns the packet's destination QPN.
    UnknownDestinationQpn(u32),
    /// A packet was delivered while the matching queue pair could not receive.
    QpNotReady(rocev2_core::QpState),
    /// Queue-pair validation or transition failed.
    QpState(StateTransitionError),
    /// Registered-memory validation or lifecycle operation failed.
    Memory(MemoryError),
    /// A fixed-capacity work or completion queue is full.
    QueueFull(QueueKind),
    /// A queue pair still owns posted work, responder state, or completions.
    QpBusy,
    /// A work request would occupy an ambiguous half-space of the 24-bit PSN ring.
    WorkRequestTooLarge {
        /// Required packet count.
        packets: u32,
        /// Maximum supported outstanding packet count.
        maximum: u32,
    },
    /// The endpoint clock frequency must be non-zero.
    InvalidTicksPerSecond,
    /// The configured generated RNR timer does not fit the five-bit AETH field.
    InvalidRnrNakTimer(u8),
    /// A QP path MTU cannot fit inside the endpoint's complete-packet limit.
    PathMtuExceedsPacketLimit {
        /// Largest complete packet required by the path MTU.
        required: usize,
        /// Endpoint complete-packet limit.
        maximum: usize,
    },
    /// A connected QP received traffic from an unexpected IPv4 peer.
    PeerAddressMismatch {
        /// Packet source address.
        source: [u8; 4],
        /// Packet destination address.
        destination: [u8; 4],
    },
}

impl fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => write!(formatter, "wire error: {error}"),
            Self::BufferTooShort { needed, actual } => {
                write!(
                    formatter,
                    "buffer too short: need {needed} bytes, got {actual}"
                )
            }
            Self::PacketTooLarge { length, maximum } => {
                write!(
                    formatter,
                    "packet length {length} exceeds maximum {maximum}"
                )
            }
            Self::UnsupportedMaximumPacket { requested, backend } => write!(
                formatter,
                "endpoint maximum {requested} exceeds backend maximum {backend}"
            ),
            Self::InvalidIpv4Protocol(protocol) => {
                write!(formatter, "IPv4 protocol {protocol} is not UDP")
            }
            Self::FragmentedIpv4 => formatter.write_str("fragmented IPv4 is not supported"),
            Self::InvalidRoceDestinationPort(port) => {
                write!(formatter, "UDP destination port {port} is not RoCEv2")
            }
            Self::InvalidUdpLength { declared, actual } => write!(
                formatter,
                "UDP length mismatch: declared {declared} bytes, IPv4 carries {actual}"
            ),
            Self::ArithmeticOverflow => formatter.write_str("packet-length arithmetic overflow"),
            Self::QpTableFull => formatter.write_str("queue-pair table is full"),
            Self::InvalidQpHandle => formatter.write_str("invalid or stale queue-pair handle"),
            Self::DuplicateLocalQpn(qpn) => {
                write!(formatter, "local queue-pair number {qpn} is already in use")
            }
            Self::UnknownDestinationQpn(qpn) => {
                write!(formatter, "no queue pair owns destination QPN {qpn}")
            }
            Self::QpNotReady(state) => {
                write!(formatter, "queue pair in state {state:?} cannot receive")
            }
            Self::QpState(error) => write!(formatter, "queue-pair state error: {error:?}"),
            Self::Memory(error) => write!(formatter, "registered-memory error: {error}"),
            Self::QueueFull(queue) => write!(formatter, "{queue:?} queue is full"),
            Self::QpBusy => {
                formatter.write_str("queue pair still owns pending work or completions")
            }
            Self::WorkRequestTooLarge { packets, maximum } => write!(
                formatter,
                "work request needs {packets} packets; maximum unambiguous span is {maximum}"
            ),
            Self::InvalidTicksPerSecond => {
                formatter.write_str("endpoint ticks_per_second must be non-zero")
            }
            Self::InvalidRnrNakTimer(timer) => {
                write!(formatter, "RNR NAK timer code {timer} exceeds five bits")
            }
            Self::PathMtuExceedsPacketLimit { required, maximum } => write!(
                formatter,
                "path MTU needs a {required}-byte packet, endpoint maximum is {maximum}"
            ),
            Self::PeerAddressMismatch {
                source,
                destination,
            } => write!(
                formatter,
                "packet peer mismatch: source={source:?}, destination={destination:?}"
            ),
        }
    }
}

impl std::error::Error for ApiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
            Self::Memory(error) => Some(error),
            _ => None,
        }
    }
}

impl From<WireError> for ApiError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

impl From<StateTransitionError> for ApiError {
    fn from(error: StateTransitionError) -> Self {
        Self::QpState(error)
    }
}

impl From<MemoryError> for ApiError {
    fn from(error: MemoryError) -> Self {
        Self::Memory(error)
    }
}

/// Error returned while polling or transmitting through a packet backend.
#[derive(Debug)]
pub enum PollError<E> {
    /// Packet backend failure.
    Io(E),
    /// Endpoint or packet validation failure.
    Api(ApiError),
}

impl<E> From<ApiError> for PollError<E> {
    fn from(error: ApiError) -> Self {
        Self::Api(error)
    }
}

impl<E: fmt::Display> fmt::Display for PollError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "packet I/O error: {error}"),
            Self::Api(error) => error.fmt(formatter),
        }
    }
}

impl<E> std::error::Error for PollError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Api(error) => Some(error),
        }
    }
}
