use crate::{AETH_LEN, BTH_LEN, RETH_LEN, WireError};

/// Reliable Connected transport opcode.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum Opcode {
    /// First packet of a multi-packet SEND.
    SendFirst = 0x00,
    /// Interior packet of a multi-packet SEND.
    SendMiddle = 0x01,
    /// Last packet of a multi-packet SEND.
    SendLast = 0x02,
    /// Last SEND packet carrying immediate data (not enabled by the v1 engine).
    SendLastWithImmediate = 0x03,
    /// Single-packet SEND.
    SendOnly = 0x04,
    /// Single-packet SEND carrying immediate data (not enabled by the v1 engine).
    SendOnlyWithImmediate = 0x05,
    /// First packet of a multi-packet RDMA WRITE.
    RdmaWriteFirst = 0x06,
    /// Interior packet of a multi-packet RDMA WRITE.
    RdmaWriteMiddle = 0x07,
    /// Last packet of a multi-packet RDMA WRITE.
    RdmaWriteLast = 0x08,
    /// Last WRITE packet carrying immediate data.
    RdmaWriteLastWithImmediate = 0x09,
    /// Single-packet RDMA WRITE.
    RdmaWriteOnly = 0x0a,
    /// Single-packet WRITE carrying immediate data.
    RdmaWriteOnlyWithImmediate = 0x0b,
    /// RDMA READ request.
    RdmaReadRequest = 0x0c,
    /// First packet of a multi-packet RDMA READ response.
    RdmaReadResponseFirst = 0x0d,
    /// Interior packet of a multi-packet RDMA READ response.
    RdmaReadResponseMiddle = 0x0e,
    /// Last packet of a multi-packet RDMA READ response.
    RdmaReadResponseLast = 0x0f,
    /// Single-packet RDMA READ response.
    RdmaReadResponseOnly = 0x10,
    /// ACK or NAK response.
    Acknowledge = 0x11,
}

/// Logical operation represented by an opcode.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Operation {
    /// SEND request.
    Send,
    /// RDMA WRITE request.
    Write,
    /// RDMA READ request.
    ReadRequest,
    /// RDMA READ response.
    ReadResponse,
    /// ACK/NAK response.
    Acknowledge,
}

/// Position of a packet inside a segmented operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SegmentPosition {
    /// First packet, with more packets following.
    First,
    /// Interior packet.
    Middle,
    /// Last packet, after at least one prior packet.
    Last,
    /// Entire operation in one packet.
    Only,
}

impl Opcode {
    /// Decode a numeric RC opcode.
    pub const fn from_u8(value: u8) -> Result<Self, WireError> {
        let opcode = match value {
            0x00 => Self::SendFirst,
            0x01 => Self::SendMiddle,
            0x02 => Self::SendLast,
            0x03 => Self::SendLastWithImmediate,
            0x04 => Self::SendOnly,
            0x05 => Self::SendOnlyWithImmediate,
            0x06 => Self::RdmaWriteFirst,
            0x07 => Self::RdmaWriteMiddle,
            0x08 => Self::RdmaWriteLast,
            0x09 => Self::RdmaWriteLastWithImmediate,
            0x0a => Self::RdmaWriteOnly,
            0x0b => Self::RdmaWriteOnlyWithImmediate,
            0x0c => Self::RdmaReadRequest,
            0x0d => Self::RdmaReadResponseFirst,
            0x0e => Self::RdmaReadResponseMiddle,
            0x0f => Self::RdmaReadResponseLast,
            0x10 => Self::RdmaReadResponseOnly,
            0x11 => Self::Acknowledge,
            _ => return Err(WireError::UnsupportedOpcode(value)),
        };
        Ok(opcode)
    }

    /// Numeric wire value.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Logical operation.
    #[must_use]
    pub const fn operation(self) -> Operation {
        match self {
            Self::SendFirst
            | Self::SendMiddle
            | Self::SendLast
            | Self::SendLastWithImmediate
            | Self::SendOnly
            | Self::SendOnlyWithImmediate => Operation::Send,
            Self::RdmaWriteFirst
            | Self::RdmaWriteMiddle
            | Self::RdmaWriteLast
            | Self::RdmaWriteLastWithImmediate
            | Self::RdmaWriteOnly
            | Self::RdmaWriteOnlyWithImmediate => Operation::Write,
            Self::RdmaReadRequest => Operation::ReadRequest,
            Self::RdmaReadResponseFirst
            | Self::RdmaReadResponseMiddle
            | Self::RdmaReadResponseLast
            | Self::RdmaReadResponseOnly => Operation::ReadResponse,
            Self::Acknowledge => Operation::Acknowledge,
        }
    }

    /// Segmentation position.
    #[must_use]
    pub const fn position(self) -> SegmentPosition {
        match self {
            Self::SendFirst | Self::RdmaWriteFirst | Self::RdmaReadResponseFirst => {
                SegmentPosition::First
            }
            Self::SendMiddle | Self::RdmaWriteMiddle | Self::RdmaReadResponseMiddle => {
                SegmentPosition::Middle
            }
            Self::SendLast
            | Self::SendLastWithImmediate
            | Self::RdmaWriteLast
            | Self::RdmaWriteLastWithImmediate
            | Self::RdmaReadResponseLast => SegmentPosition::Last,
            Self::SendOnly
            | Self::SendOnlyWithImmediate
            | Self::RdmaWriteOnly
            | Self::RdmaWriteOnlyWithImmediate
            | Self::RdmaReadRequest
            | Self::RdmaReadResponseOnly
            | Self::Acknowledge => SegmentPosition::Only,
        }
    }

    /// Whether a RETH follows the BTH.
    #[must_use]
    pub const fn has_reth(self) -> bool {
        matches!(
            self,
            Self::RdmaWriteFirst
                | Self::RdmaWriteOnly
                | Self::RdmaWriteOnlyWithImmediate
                | Self::RdmaReadRequest
        )
    }

    /// Whether an AETH follows the BTH.
    #[must_use]
    pub const fn has_aeth(self) -> bool {
        matches!(
            self,
            Self::RdmaReadResponseFirst
                | Self::RdmaReadResponseLast
                | Self::RdmaReadResponseOnly
                | Self::Acknowledge
        )
    }

    /// Whether this opcode includes an immediate-data header.
    #[must_use]
    pub const fn has_immediate(self) -> bool {
        matches!(
            self,
            Self::SendLastWithImmediate
                | Self::SendOnlyWithImmediate
                | Self::RdmaWriteLastWithImmediate
                | Self::RdmaWriteOnlyWithImmediate
        )
    }

    /// Length of transport headers before immediate data and payload.
    #[must_use]
    pub const fn fixed_header_len(self) -> usize {
        BTH_LEN
            + if self.has_reth() { RETH_LEN } else { 0 }
            + if self.has_aeth() { AETH_LEN } else { 0 }
    }

    /// Whether the opcode may carry a payload.
    #[must_use]
    pub const fn allows_payload(self) -> bool {
        !matches!(self, Self::RdmaReadRequest | Self::Acknowledge)
    }

    /// Whether this packet is sent by an RC requester.
    #[must_use]
    pub const fn is_request(self) -> bool {
        matches!(
            self.operation(),
            Operation::Send | Operation::Write | Operation::ReadRequest
        )
    }

    /// Whether this packet is sent by an RC responder.
    #[must_use]
    pub const fn is_response(self) -> bool {
        !self.is_request()
    }
}

impl TryFrom<u8> for Opcode {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::from_u8(value)
    }
}

impl From<Opcode> for u8 {
    fn from(value: Opcode) -> Self {
        value.as_u8()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rc_opcode_values_match_iba_table() {
        for value in 0_u8..=0x11 {
            assert_eq!(Opcode::from_u8(value).unwrap().as_u8(), value);
        }
        assert!(Opcode::from_u8(0x12).is_err());
    }

    #[test]
    fn extended_headers_are_classified() {
        assert!(Opcode::RdmaWriteFirst.has_reth());
        assert!(Opcode::RdmaReadRequest.has_reth());
        assert!(Opcode::RdmaReadResponseOnly.has_aeth());
        assert!(Opcode::Acknowledge.has_aeth());
        assert!(!Opcode::SendOnly.has_reth());
    }
}
