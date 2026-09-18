use crate::{AETH_LEN, Aeth, BTH_LEN, Bth, ICRC_LEN, Icrc, RETH_LEN, Reth, WireError};

/// Parser strictness controls.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseOptions {
    /// Reject non-zero pad bytes.
    pub require_zero_padding: bool,
    /// Reject payload on opcodes that must not carry one.
    pub reject_unexpected_payload: bool,
}

impl ParseOptions {
    /// Strict network-input parsing.
    pub const STRICT: Self = Self {
        require_zero_padding: true,
        reject_unexpected_payload: true,
    };
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self::STRICT
    }
}

/// Borrowed, decoded `RoCE` transport packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketRef<'a> {
    /// Base Transport Header.
    pub bth: Bth,
    /// Optional RDMA Extended Transport Header.
    pub reth: Option<Reth>,
    /// Optional ACK Extended Transport Header.
    pub aeth: Option<Aeth>,
    /// Immediate data, when the opcode carries it.
    pub immediate_data: Option<u32>,
    /// Borrowed operation payload.
    pub payload: &'a [u8],
    /// Borrowed trailing pad bytes.
    pub padding: &'a [u8],
    /// ICRC value as encoded little-endian on the wire.
    pub icrc: u32,
}

impl<'a> PacketRef<'a> {
    /// Parse a UDP payload that starts with BTH and ends with ICRC.
    pub fn parse(input: &'a [u8], options: ParseOptions) -> Result<Self, WireError> {
        if input.len() < BTH_LEN + ICRC_LEN {
            return Err(WireError::BufferTooShort {
                needed: BTH_LEN + ICRC_LEN,
                actual: input.len(),
            });
        }
        let bth = Bth::decode(input)?;
        let opcode = bth.opcode;
        let mut cursor = BTH_LEN;

        let reth = if opcode.has_reth() {
            let end = cursor
                .checked_add(RETH_LEN)
                .ok_or(WireError::ArithmeticOverflow)?;
            if end > input.len() {
                return Err(WireError::BufferTooShort {
                    needed: end,
                    actual: input.len(),
                });
            }
            let value = Reth::decode(&input[cursor..end])?;
            cursor = end;
            Some(value)
        } else {
            None
        };

        let aeth = if opcode.has_aeth() {
            let end = cursor
                .checked_add(AETH_LEN)
                .ok_or(WireError::ArithmeticOverflow)?;
            if end > input.len() {
                return Err(WireError::BufferTooShort {
                    needed: end,
                    actual: input.len(),
                });
            }
            let value = Aeth::decode(&input[cursor..end])?;
            cursor = end;
            Some(value)
        } else {
            None
        };

        let immediate_data = if opcode.has_immediate() {
            let end = cursor.checked_add(4).ok_or(WireError::ArithmeticOverflow)?;
            if end > input.len() {
                return Err(WireError::BufferTooShort {
                    needed: end,
                    actual: input.len(),
                });
            }
            let value = u32::from_be_bytes([
                input[cursor],
                input[cursor + 1],
                input[cursor + 2],
                input[cursor + 3],
            ]);
            cursor = end;
            Some(value)
        } else {
            None
        };

        let pad = usize::from(bth.pad_count);
        let trailer = pad
            .checked_add(ICRC_LEN)
            .ok_or(WireError::ArithmeticOverflow)?;
        if input.len() < cursor + trailer {
            return Err(WireError::LengthMismatch {
                expected: cursor + trailer,
                actual: input.len(),
            });
        }
        let payload_end = input.len() - trailer;
        let padding_end = input.len() - ICRC_LEN;
        let payload = &input[cursor..payload_end];
        let padding = &input[payload_end..padding_end];
        if options.reject_unexpected_payload && !opcode.allows_payload() && !payload.is_empty() {
            return Err(WireError::HeaderMismatch {
                opcode: opcode.as_u8(),
                expected: "no payload",
            });
        }
        if options.require_zero_padding && padding.iter().any(|&byte| byte != 0) {
            return Err(WireError::NonZeroPadding);
        }
        let icrc = u32::from_le_bytes([
            input[padding_end],
            input[padding_end + 1],
            input[padding_end + 2],
            input[padding_end + 3],
        ]);

        Ok(Self {
            bth,
            reth,
            aeth,
            immediate_data,
            payload,
            padding,
            icrc,
        })
    }

    /// Verify this packet's ICRC against the supplied IPv4 and UDP headers.
    pub fn verify_icrc(
        &self,
        full_transport: &[u8],
        ipv4_header: &[u8],
        udp_header: &[u8],
    ) -> Result<(), WireError> {
        if full_transport.len() < ICRC_LEN {
            return Err(WireError::BufferTooShort {
                needed: ICRC_LEN,
                actual: full_transport.len(),
            });
        }
        let computed = Icrc::compute_ipv4(
            ipv4_header,
            udp_header,
            &full_transport[..full_transport.len() - ICRC_LEN],
        )?;
        if computed != self.icrc {
            return Err(WireError::IcrcMismatch {
                wire: self.icrc,
                computed,
            });
        }
        Ok(())
    }
}

/// Packet description used by the allocation-free encoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketSpec<'a> {
    /// Base Transport Header. The encoder overwrites `pad_count` based on payload length.
    pub bth: Bth,
    /// RETH for opcodes that require one.
    pub reth: Option<Reth>,
    /// AETH for opcodes that require one.
    pub aeth: Option<Aeth>,
    /// Immediate data for opcodes that require it.
    pub immediate_data: Option<u32>,
    /// Payload bytes.
    pub payload: &'a [u8],
}

impl PacketSpec<'_> {
    /// Number of pad bytes required by the four-byte transport alignment rule.
    #[must_use]
    pub const fn pad_count(&self) -> usize {
        (4 - (self.payload.len() & 3)) & 3
    }

    /// Encoded BTH-through-ICRC length.
    pub fn encoded_len(&self) -> Result<usize, WireError> {
        let mut length = BTH_LEN;
        if self.bth.opcode.has_reth() {
            length = length
                .checked_add(RETH_LEN)
                .ok_or(WireError::ArithmeticOverflow)?;
        }
        if self.bth.opcode.has_aeth() {
            length = length
                .checked_add(AETH_LEN)
                .ok_or(WireError::ArithmeticOverflow)?;
        }
        if self.bth.opcode.has_immediate() {
            length = length.checked_add(4).ok_or(WireError::ArithmeticOverflow)?;
        }
        length = length
            .checked_add(self.payload.len())
            .and_then(|value| value.checked_add(self.pad_count()))
            .and_then(|value| value.checked_add(ICRC_LEN))
            .ok_or(WireError::ArithmeticOverflow)?;
        Ok(length)
    }

    /// Encode BTH, extended headers, payload, and padding, leaving the final ICRC blank.
    ///
    /// The return value is the number of bytes before the ICRC field. Call
    /// [`Self::encode_with_icrc`] when IPv4 and UDP headers are available.
    pub fn encode_without_icrc(&self, output: &mut [u8]) -> Result<usize, WireError> {
        self.validate_headers()?;
        let total = self.encoded_len()?;
        if output.len() < total {
            return Err(WireError::BufferTooShort {
                needed: total,
                actual: output.len(),
            });
        }

        let mut bth = self.bth;
        bth.pad_count = self.pad_count() as u8;
        bth.encode(&mut output[..BTH_LEN])?;
        let mut cursor = BTH_LEN;

        if let Some(reth) = self.reth {
            reth.encode(&mut output[cursor..cursor + RETH_LEN])?;
            cursor += RETH_LEN;
        }
        if let Some(aeth) = self.aeth {
            aeth.encode(&mut output[cursor..cursor + AETH_LEN])?;
            cursor += AETH_LEN;
        }
        if let Some(immediate) = self.immediate_data {
            output[cursor..cursor + 4].copy_from_slice(&immediate.to_be_bytes());
            cursor += 4;
        }
        output[cursor..cursor + self.payload.len()].copy_from_slice(self.payload);
        cursor += self.payload.len();
        output[cursor..cursor + self.pad_count()].fill(0);
        cursor += self.pad_count();
        output[cursor..cursor + ICRC_LEN].fill(0);
        Ok(cursor)
    }

    /// Encode a complete transport packet and calculate its IPv4 `RoCEv2` ICRC.
    pub fn encode_with_icrc(
        &self,
        ipv4_header: &[u8],
        udp_header: &[u8],
        output: &mut [u8],
    ) -> Result<usize, WireError> {
        let icrc_offset = self.encode_without_icrc(output)?;
        let icrc = Icrc::compute_ipv4(ipv4_header, udp_header, &output[..icrc_offset])?;
        output[icrc_offset..icrc_offset + ICRC_LEN].copy_from_slice(&icrc.to_le_bytes());
        Ok(icrc_offset + ICRC_LEN)
    }

    fn validate_headers(&self) -> Result<(), WireError> {
        let opcode = self.bth.opcode;
        if opcode.has_reth() != self.reth.is_some() {
            return Err(WireError::HeaderMismatch {
                opcode: opcode.as_u8(),
                expected: if opcode.has_reth() { "RETH" } else { "no RETH" },
            });
        }
        if opcode.has_aeth() != self.aeth.is_some() {
            return Err(WireError::HeaderMismatch {
                opcode: opcode.as_u8(),
                expected: if opcode.has_aeth() { "AETH" } else { "no AETH" },
            });
        }
        if opcode.has_immediate() != self.immediate_data.is_some() {
            return Err(WireError::HeaderMismatch {
                opcode: opcode.as_u8(),
                expected: if opcode.has_immediate() {
                    "immediate data"
                } else {
                    "no immediate data"
                },
            });
        }
        if !opcode.allows_payload() && !self.payload.is_empty() {
            return Err(WireError::HeaderMismatch {
                opcode: opcode.as_u8(),
                expected: "no payload",
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IPV4_HEADER_LEN, Ipv4Header, Opcode, ROCE_V2_UDP_PORT, UDP_HEADER_LEN, UdpHeader};

    #[test]
    fn write_only_roundtrip_and_icrc() {
        let payload = b"hello";
        let spec = PacketSpec {
            bth: Bth::new(Opcode::RdmaWriteOnly, 0x1234, 77),
            reth: Some(Reth {
                virtual_address: 0x1000,
                remote_key: 0xdead_beef,
                dma_length: payload.len() as u32,
            }),
            aeth: None,
            immediate_data: None,
            payload,
        };
        let transport_len = spec.encoded_len().unwrap();
        let udp_len = (UDP_HEADER_LEN + transport_len) as u16;
        let ip_len = (IPV4_HEADER_LEN + usize::from(udp_len)) as u16;
        let mut ip = [0_u8; IPV4_HEADER_LEN];
        let mut udp = [0_u8; UDP_HEADER_LEN];
        Ipv4Header::udp([192, 0, 2, 1], [192, 0, 2, 2], ip_len)
            .encode(&mut ip)
            .unwrap();
        UdpHeader {
            source_port: 50000,
            destination_port: ROCE_V2_UDP_PORT,
            length: udp_len,
            checksum: 0,
        }
        .encode(&mut udp)
        .unwrap();

        let mut packet = [0_u8; 128];
        let encoded = spec.encode_with_icrc(&ip, &udp, &mut packet).unwrap();
        assert_eq!(encoded, transport_len);
        let parsed = PacketRef::parse(&packet[..encoded], ParseOptions::STRICT).unwrap();
        assert_eq!(parsed.payload, payload);
        assert_eq!(parsed.reth, spec.reth);
        assert_eq!(parsed.padding, &[0, 0, 0]);
        parsed.verify_icrc(&packet[..encoded], &ip, &udp).unwrap();
    }

    #[test]
    fn malformed_padding_is_rejected() {
        let spec = PacketSpec {
            bth: Bth::new(Opcode::SendOnly, 1, 1),
            reth: None,
            aeth: None,
            immediate_data: None,
            payload: b"x",
        };
        let mut packet = [0_u8; 64];
        let offset = spec.encode_without_icrc(&mut packet).unwrap();
        packet[offset - 1] = 1;
        assert_eq!(
            PacketRef::parse(&packet[..offset + ICRC_LEN], ParseOptions::STRICT),
            Err(WireError::NonZeroPadding)
        );
    }
}
