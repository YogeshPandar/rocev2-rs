use crate::{BTH_LEN, Opcode, PSN_MASK, QPN_MASK, WireError};

const SE_MASK: u8 = 0x80;
const MIG_MASK: u8 = 0x40;
const PAD_MASK: u8 = 0x30;
const TVER_MASK: u8 = 0x0f;
const FECN_MASK: u32 = 0x8000_0000;
const BECN_MASK: u32 = 0x4000_0000;
const QPN_RESERVED_MASK: u32 = 0x3f00_0000;
const ACK_MASK: u32 = 0x8000_0000;
const APSN_RESERVED_MASK: u32 = 0x7f00_0000;

/// InfiniBand Base Transport Header carried by `RoCEv2`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
// The booleans model independent one-bit BTH wire fields exactly.
#[allow(clippy::struct_excessive_bools)]
pub struct Bth {
    /// RC operation opcode.
    pub opcode: Opcode,
    /// Solicited Event flag.
    pub solicited_event: bool,
    /// Migration Request flag.
    pub migration_request: bool,
    /// Number of zero pad bytes before the ICRC.
    pub pad_count: u8,
    /// Transport Header Version; currently required to be zero.
    pub transport_version: u8,
    /// Partition key. RoCE data QPs normally use `0xffff`.
    pub partition_key: u16,
    /// Forward ECN bit.
    pub fecn: bool,
    /// Backward ECN bit.
    pub becn: bool,
    /// Destination Queue Pair Number (24 bits).
    pub destination_qpn: u32,
    /// Request an ACK for this packet.
    pub ack_request: bool,
    /// Packet Sequence Number (24 bits).
    pub psn: u32,
}

impl Bth {
    /// Default full-membership partition key used by RoCE.
    pub const DEFAULT_PKEY: u16 = 0xffff;

    /// Construct a conventional RC BTH.
    #[must_use]
    pub const fn new(opcode: Opcode, destination_qpn: u32, psn: u32) -> Self {
        Self {
            opcode,
            solicited_event: false,
            migration_request: false,
            pad_count: 0,
            transport_version: 0,
            partition_key: Self::DEFAULT_PKEY,
            fecn: false,
            becn: false,
            destination_qpn,
            ack_request: false,
            psn,
        }
    }

    /// Decode a BTH and reject non-zero reserved bits.
    pub fn decode(input: &[u8]) -> Result<Self, WireError> {
        if input.len() < BTH_LEN {
            return Err(WireError::BufferTooShort {
                needed: BTH_LEN,
                actual: input.len(),
            });
        }

        let opcode = Opcode::from_u8(input[0])?;
        let flags = input[1];
        let transport_version = flags & TVER_MASK;
        if transport_version != 0 {
            return Err(WireError::InvalidTransportVersion(transport_version));
        }

        let qpn_word = u32::from_be_bytes([input[4], input[5], input[6], input[7]]);
        let qpn_reserved = qpn_word & QPN_RESERVED_MASK;
        if qpn_reserved != 0 {
            return Err(WireError::ReservedBitsSet {
                field: "BTH.qpn",
                value: qpn_reserved,
            });
        }

        let apsn_word = u32::from_be_bytes([input[8], input[9], input[10], input[11]]);
        let apsn_reserved = apsn_word & APSN_RESERVED_MASK;
        if apsn_reserved != 0 {
            return Err(WireError::ReservedBitsSet {
                field: "BTH.apsn",
                value: apsn_reserved,
            });
        }

        Ok(Self {
            opcode,
            solicited_event: flags & SE_MASK != 0,
            migration_request: flags & MIG_MASK != 0,
            pad_count: (flags & PAD_MASK) >> 4,
            transport_version,
            partition_key: u16::from_be_bytes([input[2], input[3]]),
            fecn: qpn_word & FECN_MASK != 0,
            becn: qpn_word & BECN_MASK != 0,
            destination_qpn: qpn_word & QPN_MASK,
            ack_request: apsn_word & ACK_MASK != 0,
            psn: apsn_word & PSN_MASK,
        })
    }

    /// Encode the header into the beginning of `output`.
    pub fn encode(&self, output: &mut [u8]) -> Result<(), WireError> {
        if output.len() < BTH_LEN {
            return Err(WireError::BufferTooShort {
                needed: BTH_LEN,
                actual: output.len(),
            });
        }
        if self.destination_qpn > QPN_MASK {
            return Err(WireError::ValueOutOfRange {
                field: "destination_qpn",
                value: u64::from(self.destination_qpn),
            });
        }
        if self.psn > PSN_MASK {
            return Err(WireError::ValueOutOfRange {
                field: "psn",
                value: u64::from(self.psn),
            });
        }
        if self.pad_count > 3 {
            return Err(WireError::ValueOutOfRange {
                field: "pad_count",
                value: u64::from(self.pad_count),
            });
        }
        if self.transport_version != 0 {
            return Err(WireError::InvalidTransportVersion(self.transport_version));
        }

        output[0] = self.opcode.as_u8();
        output[1] = (if self.solicited_event { SE_MASK } else { 0 })
            | (if self.migration_request { MIG_MASK } else { 0 })
            | ((self.pad_count << 4) & PAD_MASK)
            | (self.transport_version & TVER_MASK);
        output[2..4].copy_from_slice(&self.partition_key.to_be_bytes());

        let qpn_word = (if self.fecn { FECN_MASK } else { 0 })
            | (if self.becn { BECN_MASK } else { 0 })
            | self.destination_qpn;
        output[4..8].copy_from_slice(&qpn_word.to_be_bytes());

        let apsn_word = (if self.ack_request { ACK_MASK } else { 0 }) | self.psn;
        output[8..12].copy_from_slice(&apsn_word.to_be_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_bth_encoding() {
        let bth = Bth {
            opcode: Opcode::RdmaWriteOnly,
            solicited_event: true,
            migration_request: false,
            pad_count: 2,
            transport_version: 0,
            partition_key: 0xffff,
            fecn: true,
            becn: false,
            destination_qpn: 0x12_3456,
            ack_request: true,
            psn: 0xab_cdef,
        };
        let mut bytes = [0_u8; BTH_LEN];
        bth.encode(&mut bytes).unwrap();
        assert_eq!(
            bytes,
            [
                0x0a, 0xa0, 0xff, 0xff, 0x80, 0x12, 0x34, 0x56, 0x80, 0xab, 0xcd, 0xef
            ]
        );
        assert_eq!(Bth::decode(&bytes).unwrap(), bth);
    }

    #[test]
    fn reserved_bits_are_rejected() {
        let mut bytes = [0_u8; BTH_LEN];
        Bth::new(Opcode::SendOnly, 1, 2).encode(&mut bytes).unwrap();
        bytes[4] |= 0x01;
        assert!(matches!(
            Bth::decode(&bytes),
            Err(WireError::ReservedBitsSet {
                field: "BTH.qpn",
                ..
            })
        ));
    }
}
