use crate::{BTH_LEN, WireError};

/// ICRC field length.
pub const ICRC_LEN: usize = 4;
/// RoCE ICRC seed after the synthetic all-ones LRH contribution.
pub const ICRC_SEED: u32 = 0xdebb_20e3;
const CRC32_POLYNOMIAL_REFLECTED: u32 = 0xedb8_8320;

/// Incremental reflected CRC-32 used by the RoCE invariant CRC.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Icrc {
    state: u32,
}

impl Icrc {
    /// Start a RoCE ICRC calculation with the Annex A16/A17 seed.
    #[must_use]
    pub const fn new() -> Self {
        Self { state: ICRC_SEED }
    }

    /// Start a generic reflected CRC-32 calculation with a custom seed.
    #[must_use]
    pub const fn with_seed(seed: u32) -> Self {
        Self { state: seed }
    }

    /// Add bytes to the checksum.
    pub fn update(&mut self, bytes: &[u8]) {
        let mut crc = self.state;
        for &byte in bytes {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                let mask = 0_u32.wrapping_sub(crc & 1);
                crc = (crc >> 1) ^ (CRC32_POLYNOMIAL_REFLECTED & mask);
            }
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

        let mut ip = [0_u8; 60];
        ip[..ihl].copy_from_slice(&ipv4_header[..ihl]);
        // Fields declared variant by RoCE are replaced with all ones before CRC.
        ip[1] = 0xff; // DSCP/ECN
        ip[8] = 0xff; // TTL
        ip[10] = 0xff;
        ip[11] = 0xff; // IPv4 checksum

        let mut udp = [0_u8; 8];
        udp.copy_from_slice(&udp_header[..8]);
        udp[6] = 0xff;
        udp[7] = 0xff; // UDP checksum

        let mut bth = [0_u8; BTH_LEN];
        bth.copy_from_slice(&transport_without_icrc[..BTH_LEN]);
        // BTH.resv8a (the six bits above QPN) is replaced with all ones.
        bth[4] |= 0x3f;

        let mut crc = Self::new();
        crc.update(&ip[..ihl]);
        crc.update(&udp);
        crc.update(&bth);
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
}
