use core::fmt;

/// Error returned while decoding or encoding a wire object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WireError {
    /// The supplied buffer was shorter than required.
    BufferTooShort {
        /// Minimum required length.
        needed: usize,
        /// Supplied length.
        actual: usize,
    },
    /// The BTH opcode is not supported by this RC-only implementation.
    UnsupportedOpcode(u8),
    /// The BTH transport-header version is not zero.
    InvalidTransportVersion(u8),
    /// A 24-bit field exceeded its wire width.
    ValueOutOfRange {
        /// Field name.
        field: &'static str,
        /// Rejected value.
        value: u64,
    },
    /// Reserved bits that must be zero were non-zero.
    ReservedBitsSet {
        /// Header/field name.
        field: &'static str,
        /// Observed reserved bits.
        value: u32,
    },
    /// The opcode and supplied extended header disagree.
    HeaderMismatch {
        /// Numeric opcode.
        opcode: u8,
        /// Expected header description.
        expected: &'static str,
    },
    /// A packet length field or encoded size was inconsistent.
    LengthMismatch {
        /// Declared or expected length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },
    /// The packet contains non-zero pad bytes in strict mode.
    NonZeroPadding,
    /// The packet ICRC did not match the computed value.
    IcrcMismatch {
        /// ICRC found on the wire.
        wire: u32,
        /// Locally computed ICRC.
        computed: u32,
    },
    /// The IPv4 header is malformed.
    InvalidIpv4Header,
    /// IPv4 options are unsupported by the requested operation.
    UnsupportedIpv4Options,
    /// An arithmetic operation overflowed.
    ArithmeticOverflow,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooShort { needed, actual } => {
                write!(f, "buffer too short: need {needed} bytes, got {actual}")
            }
            Self::UnsupportedOpcode(opcode) => write!(f, "unsupported RC opcode 0x{opcode:02x}"),
            Self::InvalidTransportVersion(version) => {
                write!(f, "unsupported BTH transport version {version}")
            }
            Self::ValueOutOfRange { field, value } => {
                write!(f, "{field} value {value} does not fit its wire field")
            }
            Self::ReservedBitsSet { field, value } => {
                write!(f, "reserved bits set in {field}: 0x{value:x}")
            }
            Self::HeaderMismatch { opcode, expected } => {
                write!(f, "opcode 0x{opcode:02x} requires {expected}")
            }
            Self::LengthMismatch { expected, actual } => {
                write!(f, "length mismatch: expected {expected}, got {actual}")
            }
            Self::NonZeroPadding => f.write_str("packet contains non-zero pad bytes"),
            Self::IcrcMismatch { wire, computed } => {
                write!(f, "ICRC mismatch: wire=0x{wire:08x}, computed=0x{computed:08x}")
            }
            Self::InvalidIpv4Header => f.write_str("invalid IPv4 header"),
            Self::UnsupportedIpv4Options => f.write_str("IPv4 options are not supported"),
            Self::ArithmeticOverflow => f.write_str("wire-length arithmetic overflow"),
        }
    }
}
