use crate::{BTH_LEN, WireError};

/// ICRC field length.
pub const ICRC_LEN: usize = 4;
/// `RoCE` ICRC seed after the synthetic all-ones LRH contribution.
pub const ICRC_SEED: u32 = 0xdebb_20e3;
const CRC32_POLYNOMIAL_REFLECTED: u32 = 0xedb8_8320;

// Each row advances the reflected CRC by one more byte.
static TABLES: [[u32; 256]; 8] = crc_tables();

const fn crc_tables() -> [[u32; 256]; 8] {
    let mut tables = [[0; 256]; 8];
    let mut index = 0;
    while index < 256 {
        let mut crc = index as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = (crc >> 1) ^ (CRC32_POLYNOMIAL_REFLECTED & 0_u32.wrapping_sub(crc & 1));
            bit += 1;
        }
        tables[0][index] = crc;
        index += 1;
    }
    let mut row = 1;
    while row < 8 {
        index = 0;
        while index < 256 {
            let previous = tables[row - 1][index];
            tables[row][index] = (previous >> 8) ^ tables[0][(previous & 0xff) as usize];
            index += 1;
        }
        row += 1;
    }
    tables
}

/// Incremental reflected CRC-32 used by the `RoCE` invariant CRC.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Icrc {
    state: u32,
}

impl Icrc {
    /// Start a `RoCE` ICRC calculation with the Annex A16/A17 seed.
    #[must_use]
    pub const fn new() -> Self {
        Self { state: ICRC_SEED }
    }

    /// Start a generic reflected CRC-32 calculation with a custom seed.
    #[must_use]
    pub const fn with_seed(seed: u32) -> Self {
        Self { state: seed }
    }

    /// Add bytes using a portable slicing-by-eight CRC-32 table.
    ///
    /// Input alignment is unrestricted. This is IEEE CRC-32, not CRC-32C.
    pub fn update(&mut self, bytes: &[u8]) {
        let mut crc = self.state;
        let mut chunks = bytes.chunks_exact(8);
        for chunk in &mut chunks {
            let head = crc ^ u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let octets = head.to_le_bytes();
            crc = TABLES[7][usize::from(octets[0])]
                ^ TABLES[6][usize::from(octets[1])]
                ^ TABLES[5][usize::from(octets[2])]
                ^ TABLES[4][usize::from(octets[3])]
                ^ TABLES[3][usize::from(chunk[4])]
                ^ TABLES[2][usize::from(chunk[5])]
                ^ TABLES[1][usize::from(chunk[6])]
                ^ TABLES[0][usize::from(chunk[7])];
        }
        for &byte in chunks.remainder() {
            crc = (crc >> 8) ^ TABLES[0][usize::from((crc as u8) ^ byte)];
        }
        self.state = crc;
    }

    /// Return the uncomplemented running state.
    #[must_use]
    pub const fn state(self) -> u32 {
        self.state
    }

    /// Finish the ICRC by complementing the running state.
    #[must_use]
    pub const fn finalize(self) -> u32 {
        !self.state
    }

    /// Compute an IPv4 `RoCEv2` ICRC over IPv4, UDP, and transport bytes.
    ///
    /// `transport_without_icrc` starts at the BTH and includes any payload and
    /// zero padding, but excludes the four-byte ICRC field itself.
    pub fn compute_ipv4(
        ipv4_header: &[u8],
        udp_header: &[u8],
        transport_without_icrc: &[u8],
    ) -> Result<u32, WireError> {
        if ipv4_header.len() < 20 || ipv4_header[0] >> 4 != 4 {
            return Err(WireError::InvalidIpv4Header);
        }
        let ihl = usize::from(ipv4_header[0] & 0x0f) * 4;
        if !(20..=60).contains(&ihl) || ipv4_header.len() < ihl {
            return Err(WireError::InvalidIpv4Header);
        }
        if udp_header.len() < 8 {
            return Err(WireError::BufferTooShort {
                needed: 8,
                actual: udp_header.len(),
            });
        }
        if transport_without_icrc.len() < BTH_LEN {
            return Err(WireError::BufferTooShort {
                needed: BTH_LEN,
                actual: transport_without_icrc.len(),
            });
        }

        let bth_offset = ihl + 8;
        let header_length = bth_offset + BTH_LEN;
        let mut headers = [0_u8; 60 + 8 + BTH_LEN];
        headers[..ihl].copy_from_slice(&ipv4_header[..ihl]);
        headers[ihl..bth_offset].copy_from_slice(&udp_header[..8]);
        headers[bth_offset..header_length].copy_from_slice(&transport_without_icrc[..BTH_LEN]);
        // Mask the variant IPv4, UDP, and full BTH resv8a octet as Linux RXE does.
        headers[1] = 0xff;
        headers[8] = 0xff;
        headers[10..12].fill(0xff);
        headers[ihl + 6..ihl + 8].fill(0xff);
        headers[bth_offset + 4] = 0xff;

        let mut crc = Self::new();
        crc.update(&headers[..header_length]);
        crc.update(&transport_without_icrc[BTH_LEN..]);
        Ok(crc.finalize())
    }
}

impl Default for Icrc {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Bth, IPV4_HEADER_LEN, Ipv4Header, Opcode, UDP_HEADER_LEN, UdpHeader};

    #[test]
    fn generic_crc32_matches_standard_check_value() {
        let mut crc = Icrc::with_seed(u32::MAX);
        crc.update(b"123456789");
        assert_eq!(crc.finalize(), 0xcbf4_3926);
    }

    #[test]
    fn icrc_masks_variant_ipv4_and_udp_fields() {
        let mut transport = [0_u8; BTH_LEN];
        Bth::new(Opcode::SendOnly, 7, 9)
            .encode(&mut transport)
            .unwrap();

        let ip_header = Ipv4Header::udp([192, 0, 2, 1], [198, 51, 100, 2], 40);
        let udp_header = UdpHeader {
            source_port: 50000,
            destination_port: 4791,
            length: 20,
            checksum: 0,
        };
        let mut ip = [0_u8; IPV4_HEADER_LEN];
        let mut udp = [0_u8; UDP_HEADER_LEN];
        ip_header.encode(&mut ip).unwrap();
        udp_header.encode(&mut udp).unwrap();
        let baseline = Icrc::compute_ipv4(&ip, &udp, &transport).unwrap();

        ip[1] = 0x55;
        ip[8] = 1;
        ip[10] = 0x12;
        ip[11] = 0x34;
        udp[6] = 0x56;
        udp[7] = 0x78;
        let changed = Icrc::compute_ipv4(&ip, &udp, &transport).unwrap();
        assert_eq!(baseline, changed);

        ip[12] ^= 1;
        let address_changed = Icrc::compute_ipv4(&ip, &udp, &transport).unwrap();
        assert_ne!(baseline, address_changed);
    }
    fn reference(mut crc: u32, bytes: &[u8]) -> u32 {
        for &byte in bytes {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ (CRC32_POLYNOMIAL_REFLECTED & 0_u32.wrapping_sub(crc & 1));
            }
        }
        crc
    }

    #[test]
    fn slicing_matches_bitwise_for_lengths_alignments_seeds_and_splits() {
        let mut bytes = [0_u8; 4104];
        let mut state = 0x1234_5678_u32;
        for byte in &mut bytes {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *byte = state as u8;
        }
        for length in (0..=257).chain([511, 512, 513, 1023, 1024, 1500, 2048, 4096]) {
            for offset in 0..8 {
                let input = &bytes[offset..offset + length];
                for seed in [0, u32::MAX, ICRC_SEED] {
                    let expected = reference(seed, input);
                    let mut crc = Icrc::with_seed(seed);
                    crc.update(input);
                    assert_eq!(crc.state(), expected);
                    for split in [0, length / 2, length] {
                        let mut incremental = Icrc::with_seed(seed);
                        incremental.update(&input[..split]);
                        incremental.update(&input[split..]);
                        assert_eq!(incremental.state(), expected);
                    }
                }
            }
        }
    }

    #[test]
    fn independent_rxe_masked_header_vector_and_congestion_bits() {
        // Generated independently with zlib over eight FF bytes and masked headers.
        let ip = [
            0x45, 0, 0, 44, 0, 0, 0x40, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2,
        ];
        let udp = [0xc3, 0x50, 0x12, 0xb7, 0, 24, 0, 0];
        let mut bth = [4, 0, 0xff, 0xff, 0, 0, 0, 7, 0, 0, 0, 9];
        for congestion in [0, 0x40, 0x80, 0xc0] {
            bth[4] = congestion;
            assert_eq!(Icrc::compute_ipv4(&ip, &udp, &bth), Ok(0x94bf_304a));
        }
        bth[7] ^= 1;
        assert_ne!(Icrc::compute_ipv4(&ip, &udp, &bth), Ok(0x94bf_304a));
    }
}
