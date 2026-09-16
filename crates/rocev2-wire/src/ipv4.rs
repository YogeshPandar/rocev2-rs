use crate::WireError;

/// Fixed IPv4 header length used by the v1 RoCEv2 data path.
pub const IPV4_HEADER_LEN: usize = 20;
/// UDP header length.
pub const UDP_HEADER_LEN: usize = 8;
/// IPv4 protocol number for UDP.
pub const IP_PROTOCOL_UDP: u8 = 17;

/// Minimal IPv4 header without options.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4Header {
    /// DSCP and ECN octet.
    pub dscp_ecn: u8,
    /// Total IPv4 packet length.
    pub total_length: u16,
    /// Identification field.
    pub identification: u16,
    /// Do-not-fragment flag.
    pub dont_fragment: bool,
    /// More-fragments flag.
    pub more_fragments: bool,
    /// Fragment offset in eight-byte units.
    pub fragment_offset: u16,
    /// Time to live.
    pub ttl: u8,
    /// Protocol number, normally UDP (17).
    pub protocol: u8,
    /// Source IPv4 address.
    pub source: [u8; 4],
    /// Destination IPv4 address.
    pub destination: [u8; 4],
}

impl Ipv4Header {
    /// Construct a non-fragmented UDP header.
    pub const fn udp(source: [u8; 4], destination: [u8; 4], total_length: u16) -> Self {
        Self {
            dscp_ecn: 0,
            total_length,
            identification: 0,
            dont_fragment: true,
            more_fragments: false,
            fragment_offset: 0,
            ttl: 64,
            protocol: IP_PROTOCOL_UDP,
            source,
            destination,
        }
    }

    /// Decode a fixed-size IPv4 header and validate its checksum.
    pub fn decode(input: &[u8]) -> Result<Self, WireError> {
        if input.len() < IPV4_HEADER_LEN {
            return Err(WireError::BufferTooShort {
                needed: IPV4_HEADER_LEN,
                actual: input.len(),
            });
        }
        if input[0] >> 4 != 4 {
            return Err(WireError::InvalidIpv4Header);
        }
        if input[0] & 0x0f != 5 {
            return Err(WireError::UnsupportedIpv4Options);
        }
        if internet_checksum(&input[..IPV4_HEADER_LEN]) != 0 {
            return Err(WireError::InvalidIpv4Header);
        }
        let flags_fragment = u16::from_be_bytes([input[6], input[7]]);
        Ok(Self {
            dscp_ecn: input[1],
            total_length: u16::from_be_bytes([input[2], input[3]]),
            identification: u16::from_be_bytes([input[4], input[5]]),
            dont_fragment: flags_fragment & 0x4000 != 0,
            more_fragments: flags_fragment & 0x2000 != 0,
            fragment_offset: flags_fragment & 0x1fff,
            ttl: input[8],
            protocol: input[9],
            source: input[12..16].try_into().expect("slice length"),
            destination: input[16..20].try_into().expect("slice length"),
        })
    }

    /// Encode a fixed-size IPv4 header and calculate its checksum.
    pub fn encode(&self, output: &mut [u8]) -> Result<(), WireError> {
        if output.len() < IPV4_HEADER_LEN {
            return Err(WireError::BufferTooShort {
                needed: IPV4_HEADER_LEN,
                actual: output.len(),
            });
        }
        if self.fragment_offset > 0x1fff {
            return Err(WireError::ValueOutOfRange {
                field: "fragment_offset",
                value: u64::from(self.fragment_offset),
            });
        }
        output[..IPV4_HEADER_LEN].fill(0);
        output[0] = 0x45;
        output[1] = self.dscp_ecn;
        output[2..4].copy_from_slice(&self.total_length.to_be_bytes());
        output[4..6].copy_from_slice(&self.identification.to_be_bytes());
        let flags_fragment = (if self.dont_fragment { 0x4000 } else { 0 })
            | (if self.more_fragments { 0x2000 } else { 0 })
            | self.fragment_offset;
        output[6..8].copy_from_slice(&flags_fragment.to_be_bytes());
        output[8] = self.ttl;
        output[9] = self.protocol;
        output[12..16].copy_from_slice(&self.source);
        output[16..20].copy_from_slice(&self.destination);
        let checksum = internet_checksum(&output[..IPV4_HEADER_LEN]);
        output[10..12].copy_from_slice(&checksum.to_be_bytes());
        Ok(())
    }
}

/// UDP header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpHeader {
    /// Source UDP port. RoCEv2 commonly derives this from a flow hash.
    pub source_port: u16,
    /// Destination UDP port; normally 4791.
    pub destination_port: u16,
    /// UDP datagram length, including this header.
    pub length: u16,
    /// UDP checksum. IPv4 permits zero, but hardware may emit a checksum.
    pub checksum: u16,
}

impl UdpHeader {
    /// Decode a UDP header.
    pub fn decode(input: &[u8]) -> Result<Self, WireError> {
        if input.len() < UDP_HEADER_LEN {
            return Err(WireError::BufferTooShort {
                needed: UDP_HEADER_LEN,
                actual: input.len(),
            });
        }
        Ok(Self {
            source_port: u16::from_be_bytes([input[0], input[1]]),
            destination_port: u16::from_be_bytes([input[2], input[3]]),
            length: u16::from_be_bytes([input[4], input[5]]),
            checksum: u16::from_be_bytes([input[6], input[7]]),
        })
    }

    /// Encode a UDP header.
    pub fn encode(&self, output: &mut [u8]) -> Result<(), WireError> {
        if output.len() < UDP_HEADER_LEN {
            return Err(WireError::BufferTooShort {
                needed: UDP_HEADER_LEN,
                actual: output.len(),
            });
        }
        output[0..2].copy_from_slice(&self.source_port.to_be_bytes());
        output[2..4].copy_from_slice(&self.destination_port.to_be_bytes());
        output[4..6].copy_from_slice(&self.length.to_be_bytes());
        output[6..8].copy_from_slice(&self.checksum.to_be_bytes());
        Ok(())
    }
}

/// Compute the RFC 1071 Internet checksum.
pub fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += u32::from(last) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_roundtrip() {
        let header = Ipv4Header::udp([192, 0, 2, 1], [198, 51, 100, 2], 128);
        let mut bytes = [0_u8; IPV4_HEADER_LEN];
        header.encode(&mut bytes).unwrap();
        assert_eq!(internet_checksum(&bytes), 0);
        assert_eq!(Ipv4Header::decode(&bytes).unwrap(), header);
    }

    #[test]
    fn udp_roundtrip() {
        let header = UdpHeader {
            source_port: 49152,
            destination_port: 4791,
            length: 100,
            checksum: 0,
        };
        let mut bytes = [0_u8; UDP_HEADER_LEN];
        header.encode(&mut bytes).unwrap();
        assert_eq!(UdpHeader::decode(&bytes).unwrap(), header);
    }
}
