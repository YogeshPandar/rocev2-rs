use crate::{AETH_LEN, PSN_MASK, WireError};

/// High-level AETH syndrome classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AethClass {
    /// Positive acknowledgment; the lower five bits encode receive credits.
    Ack {
        /// Advertised receive credit value.
        credit: u8,
    },
    /// Receiver-not-ready NAK; lower five bits encode the RNR timer.
    RnrNak {
        /// Five-bit receiver-not-ready delay code.
        timer: u8,
    },
    /// Reserved syndrome class.
    Reserved {
        /// Preserved lower-five-bit syndrome value.
        code: u8,
    },
    /// Negative acknowledgment.
    Nak(NakCode),
}

/// Defined RC NAK reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NakCode {
    /// Packet sequence error.
    PsnSequenceError,
    /// Invalid request.
    InvalidRequest,
    /// Remote access error.
    RemoteAccessError,
    /// Remote operation error.
    RemoteOperationError,
    /// Unknown lower-five-bit NAK code.
    Unknown(u8),
}

/// ACK Extended Transport Header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Aeth {
    /// Raw eight-bit syndrome.
    pub syndrome: u8,
    /// Message Sequence Number (24 bits).
    pub message_sequence_number: u32,
}

impl Aeth {
    /// ACK with unlimited receive credits.
    pub const ACK_UNLIMITED: u8 = 0x1f;
    /// RNR NAK class mask.
    pub const RNR_NAK: u8 = 0x20;
    /// PSN sequence-error NAK.
    pub const NAK_PSN_SEQUENCE_ERROR: u8 = 0x60;
    /// Invalid-request NAK.
    pub const NAK_INVALID_REQUEST: u8 = 0x61;
    /// Remote-access-error NAK.
    pub const NAK_REMOTE_ACCESS_ERROR: u8 = 0x62;
    /// Remote-operation-error NAK.
    pub const NAK_REMOTE_OPERATION_ERROR: u8 = 0x63;

    /// Construct an unlimited-credit ACK.
    #[must_use]
    pub const fn ack(message_sequence_number: u32) -> Self {
        Self {
            syndrome: Self::ACK_UNLIMITED,
            message_sequence_number,
        }
    }

    /// Construct an RNR NAK.
    #[must_use]
    pub const fn rnr_nak(message_sequence_number: u32, timer: u8) -> Self {
        Self {
            syndrome: Self::RNR_NAK | (timer & 0x1f),
            message_sequence_number,
        }
    }

    /// Construct a PSN sequence-error NAK.
    #[must_use]
    pub const fn psn_nak(message_sequence_number: u32) -> Self {
        Self {
            syndrome: Self::NAK_PSN_SEQUENCE_ERROR,
            message_sequence_number,
        }
    }

    /// Decode an AETH.
    pub fn decode(input: &[u8]) -> Result<Self, WireError> {
        if input.len() < AETH_LEN {
            return Err(WireError::BufferTooShort {
                needed: AETH_LEN,
                actual: input.len(),
            });
        }
        let raw = u32::from_be_bytes([input[0], input[1], input[2], input[3]]);
        Ok(Self {
            syndrome: (raw >> 24) as u8,
            message_sequence_number: raw & PSN_MASK,
        })
    }

    /// Encode an AETH.
    pub fn encode(&self, output: &mut [u8]) -> Result<(), WireError> {
        if output.len() < AETH_LEN {
            return Err(WireError::BufferTooShort {
                needed: AETH_LEN,
                actual: output.len(),
            });
        }
        if self.message_sequence_number > PSN_MASK {
            return Err(WireError::ValueOutOfRange {
                field: "message_sequence_number",
                value: u64::from(self.message_sequence_number),
            });
        }
        let raw = (u32::from(self.syndrome) << 24) | self.message_sequence_number;
        output[0..4].copy_from_slice(&raw.to_be_bytes());
        Ok(())
    }

    /// Classify the syndrome without discarding implementation-defined values.
    #[must_use]
    pub const fn class(self) -> AethClass {
        match self.syndrome & 0xe0 {
            0x00 => AethClass::Ack {
                credit: self.syndrome & 0x1f,
            },
            0x20 => AethClass::RnrNak {
                timer: self.syndrome & 0x1f,
            },
            0x40 => AethClass::Reserved {
                code: self.syndrome & 0x1f,
            },
            _ => AethClass::Nak(match self.syndrome & 0x1f {
                0 => NakCode::PsnSequenceError,
                1 => NakCode::InvalidRequest,
                2 => NakCode::RemoteAccessError,
                3 => NakCode::RemoteOperationError,
                other => NakCode::Unknown(other),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aeth_roundtrip_and_classification() {
        let aeth = Aeth::rnr_nak(0x12_3456, 7);
        let mut bytes = [0_u8; AETH_LEN];
        aeth.encode(&mut bytes).unwrap();
        assert_eq!(bytes, [0x27, 0x12, 0x34, 0x56]);
        assert_eq!(Aeth::decode(&bytes).unwrap(), aeth);
        assert_eq!(aeth.class(), AethClass::RnrNak { timer: 7 });
    }

    #[test]
    fn nak_codes_are_preserved() {
        let aeth = Aeth {
            syndrome: Aeth::NAK_REMOTE_ACCESS_ERROR,
            message_sequence_number: 0,
        };
        assert_eq!(aeth.class(), AethClass::Nak(NakCode::RemoteAccessError));
    }
}
