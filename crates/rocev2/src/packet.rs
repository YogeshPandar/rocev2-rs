//! Complete IPv4/UDP/RoCEv2 packet encoding and decoding.

use crate::ApiError;
use rocev2_wire::{
    IP_PROTOCOL_UDP, IPV4_HEADER_LEN, Ipv4Header, PacketRef, PacketSpec, ParseOptions,
    ROCE_V2_UDP_PORT, UDP_HEADER_LEN, UdpHeader,
};

/// Minimum complete IPv4 packet carrying BTH and ICRC.
pub const MIN_ROCE_IPV4_PACKET: usize = IPV4_HEADER_LEN + UDP_HEADER_LEN + 12 + 4;

/// IPv4 and UDP fields used when encoding one RoCEv2 packet.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Ipv4Path {
    /// Source IPv4 address.
    pub source: [u8; 4],
    /// Destination IPv4 address.
    pub destination: [u8; 4],
    /// UDP source port used for flow entropy.
    pub source_port: u16,
    /// IPv4 time to live.
    pub ttl: u8,
    /// IPv4 DSCP and ECN octet.
    pub dscp_ecn: u8,
}

impl Ipv4Path {
    /// Create a path with TTL 64 and no DSCP or ECN markings.
    #[must_use]
    pub const fn new(source: [u8; 4], destination: [u8; 4], source_port: u16) -> Self {
        Self {
            source,
            destination,
            source_port,
            ttl: 64,
            dscp_ecn: 0,
        }
    }
}

/// Borrowed, validated complete RoCEv2 packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodedPacket<'a> {
    /// Validated fixed-size IPv4 header.
    pub ipv4: Ipv4Header,
    /// Decoded UDP header.
    pub udp: UdpHeader,
    /// Decoded transport headers and borrowed operation payload.
    pub transport: PacketRef<'a>,
}

/// Decode and validate a complete IPv4 RoCEv2 packet.
///
/// The decoder rejects IPv4 options and fragmentation, requires an exact IPv4
/// and UDP length match, requires UDP destination port 4791, parses transport
/// headers in strict mode, and verifies the packet ICRC.
pub fn decode_ipv4_packet(input: &[u8]) -> Result<DecodedPacket<'_>, ApiError> {
    if input.len() < MIN_ROCE_IPV4_PACKET {
        return Err(ApiError::BufferTooShort {
            needed: MIN_ROCE_IPV4_PACKET,
            actual: input.len(),
        });
    }

    let ipv4_bytes = &input[..IPV4_HEADER_LEN];
    let ipv4 = Ipv4Header::decode(ipv4_bytes)?;
    if ipv4.protocol != IP_PROTOCOL_UDP {
        return Err(ApiError::InvalidIpv4Protocol(ipv4.protocol));
    }
    if ipv4.more_fragments || ipv4.fragment_offset != 0 {
        return Err(ApiError::FragmentedIpv4);
    }

    let ipv4_length = usize::from(ipv4.total_length);
    if ipv4_length != input.len() {
        return Err(rocev2_wire::WireError::LengthMismatch {
            expected: ipv4_length,
            actual: input.len(),
        }
        .into());
    }

    let udp_start = IPV4_HEADER_LEN;
    let transport_start = udp_start + UDP_HEADER_LEN;
    let udp_bytes = &input[udp_start..transport_start];
    let udp = UdpHeader::decode(udp_bytes)?;
    if udp.destination_port != ROCE_V2_UDP_PORT {
        return Err(ApiError::InvalidRoceDestinationPort(udp.destination_port));
    }

    let actual_udp_length = ipv4_length
        .checked_sub(IPV4_HEADER_LEN)
        .ok_or(ApiError::ArithmeticOverflow)?;
    let declared_udp_length = usize::from(udp.length);
    if declared_udp_length < UDP_HEADER_LEN || declared_udp_length != actual_udp_length {
        return Err(ApiError::InvalidUdpLength {
            declared: declared_udp_length,
            actual: actual_udp_length,
        });
    }

    let transport_bytes = &input[transport_start..ipv4_length];
    let transport = PacketRef::parse(transport_bytes, ParseOptions::STRICT)?;
    transport.verify_icrc(transport_bytes, ipv4_bytes, udp_bytes)?;

    Ok(DecodedPacket {
        ipv4,
        udp,
        transport,
    })
}

/// Encode a complete IPv4/UDP/RoCEv2 packet into caller-owned storage.
///
/// IPv4 fragmentation is disabled and the IPv4 UDP checksum is emitted as
/// zero, which is valid for IPv4. The RoCEv2 ICRC is always calculated.
pub fn encode_ipv4_packet(
    path: Ipv4Path,
    transport: PacketSpec<'_>,
    output: &mut [u8],
) -> Result<usize, ApiError> {
    let transport_length = transport.encoded_len()?;
    let udp_length = UDP_HEADER_LEN
        .checked_add(transport_length)
        .ok_or(ApiError::ArithmeticOverflow)?;
    let total_length = IPV4_HEADER_LEN
        .checked_add(udp_length)
        .ok_or(ApiError::ArithmeticOverflow)?;

    let udp_length_u16 = u16::try_from(udp_length).map_err(|_| ApiError::PacketTooLarge {
        length: total_length,
        maximum: usize::from(u16::MAX),
    })?;
    let total_length_u16 = u16::try_from(total_length).map_err(|_| ApiError::PacketTooLarge {
        length: total_length,
        maximum: usize::from(u16::MAX),
    })?;

    if output.len() < total_length {
        return Err(ApiError::BufferTooShort {
            needed: total_length,
            actual: output.len(),
        });
    }

    let mut ipv4 = Ipv4Header::udp(path.source, path.destination, total_length_u16);
    ipv4.ttl = path.ttl;
    ipv4.dscp_ecn = path.dscp_ecn;
    let udp = UdpHeader {
        source_port: path.source_port,
        destination_port: ROCE_V2_UDP_PORT,
        length: udp_length_u16,
        checksum: 0,
    };

    let mut ipv4_bytes = [0_u8; IPV4_HEADER_LEN];
    let mut udp_bytes = [0_u8; UDP_HEADER_LEN];
    ipv4.encode(&mut ipv4_bytes)?;
    udp.encode(&mut udp_bytes)?;
    output[..IPV4_HEADER_LEN].copy_from_slice(&ipv4_bytes);
    output[IPV4_HEADER_LEN..IPV4_HEADER_LEN + UDP_HEADER_LEN].copy_from_slice(&udp_bytes);

    let encoded_transport = transport.encode_with_icrc(
        &ipv4_bytes,
        &udp_bytes,
        &mut output[IPV4_HEADER_LEN + UDP_HEADER_LEN..total_length],
    )?;
    debug_assert_eq!(encoded_transport, transport_length);
    Ok(total_length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocev2_wire::{Bth, Opcode};

    fn packet_spec<'a>(payload: &'a [u8]) -> PacketSpec<'a> {
        PacketSpec {
            bth: Bth::new(Opcode::SendOnly, 2, 7),
            reth: None,
            aeth: None,
            immediate_data: None,
            payload,
        }
    }

    #[test]
    fn complete_packet_roundtrip_verifies_icrc() {
        let path = Ipv4Path::new([192, 0, 2, 1], [198, 51, 100, 2], 49_152);
        let mut output = [0_u8; 256];
        let length = encode_ipv4_packet(path, packet_spec(b"hello"), &mut output).unwrap();
        let decoded = decode_ipv4_packet(&output[..length]).unwrap();

        assert_eq!(decoded.ipv4.source, path.source);
        assert_eq!(decoded.ipv4.destination, path.destination);
        assert_eq!(decoded.udp.source_port, path.source_port);
        assert_eq!(decoded.transport.payload, b"hello");
        assert_eq!(decoded.transport.bth.destination_qpn, 2);
    }

    #[test]
    fn rejects_wrong_udp_destination() {
        let path = Ipv4Path::new([192, 0, 2, 1], [198, 51, 100, 2], 49_152);
        let mut output = [0_u8; 256];
        let length = encode_ipv4_packet(path, packet_spec(&[]), &mut output).unwrap();
        output[22..24].copy_from_slice(&1234_u16.to_be_bytes());

        assert_eq!(
            decode_ipv4_packet(&output[..length]),
            Err(ApiError::InvalidRoceDestinationPort(1234))
        );
    }

    #[test]
    fn rejects_inconsistent_udp_length() {
        let path = Ipv4Path::new([192, 0, 2, 1], [198, 51, 100, 2], 49_152);
        let mut output = [0_u8; 256];
        let length = encode_ipv4_packet(path, packet_spec(&[]), &mut output).unwrap();
        let declared = u16::from_be_bytes([output[24], output[25]]) - 1;
        output[24..26].copy_from_slice(&declared.to_be_bytes());

        assert!(matches!(
            decode_ipv4_packet(&output[..length]),
            Err(ApiError::InvalidUdpLength { .. })
        ));
    }

    #[test]
    fn detects_icrc_corruption() {
        let path = Ipv4Path::new([192, 0, 2, 1], [198, 51, 100, 2], 49_152);
        let mut output = [0_u8; 256];
        let length = encode_ipv4_packet(path, packet_spec(b"payload"), &mut output).unwrap();
        output[length - 1] ^= 0x80;

        assert!(matches!(
            decode_ipv4_packet(&output[..length]),
            Err(ApiError::Wire(rocev2_wire::WireError::IcrcMismatch { .. }))
        ));
    }
}
