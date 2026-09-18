//! Versioned out-of-band RC metadata; this is not RDMA-CM or authentication.

use crate::{Ipv4Path, PathMtu, Psn, QpConfig, RcQpConfig};
use core::fmt;

/// Encoded version-one connection record size.
pub const RC_CONNECTION_INFO_LEN: usize = 64;

/// Explicit connection parameters for an IPv4 RC peer.
///
/// Integer fields use network byte order. The encoding is independent of Rust
/// layout and rejects nonzero reserved bytes. Exchange only over a trusted
/// control channel: an rkey is not an authentication credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RcConnectionInfo {
    /// Local unicast IPv4 address.
    pub ipv4: [u8; 4],
    /// Local MAC, or all zeroes when the backend resolves Ethernet itself.
    pub mac: [u8; 6],
    /// Local application QPN.
    pub qpn: u32,
    /// Initial local requester PSN.
    pub psn: u32,
    /// Path MTU in payload bytes.
    pub mtu: u16,
    /// Exported remote key.
    pub rkey: u32,
    /// Exported memory base address.
    pub remote_address: u64,
    /// Exported memory extent.
    pub remote_length: u64,
    /// Local transport retry code.
    pub retry_count: u8,
    /// Local RNR retry code.
    pub rnr_retry_count: u8,
    /// Local ACK timeout code.
    pub timeout: u8,
    /// Advertised requester READ depth; version one supports exactly one.
    pub max_rd_atomic: u8,
    /// Advertised responder READ depth; version one supports exactly one.
    pub max_dest_rd_atomic: u8,
    /// Local responder RNR timer code.
    pub rnr_nak_timer: u8,
    /// UDP source port used by this requester.
    pub udp_source_port: u16,
}

/// Invalid out-of-band connection metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionInfoError {
    /// The record does not have the exact encoded size.
    Length,
    /// Magic or version is unsupported.
    Version,
    /// A reserved byte is nonzero.
    Reserved,
    /// A field lies outside the supported protocol subset.
    Field(&'static str),
}

impl fmt::Display for ConnectionInfoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length => f.write_str("invalid RC connection record length"),
            Self::Version => f.write_str("unsupported RC connection record version"),
            Self::Reserved => f.write_str("nonzero RC connection reserved field"),
            Self::Field(field) => write!(f, "invalid RC connection field: {field}"),
        }
    }
}

impl core::error::Error for ConnectionInfoError {}

impl RcConnectionInfo {
    /// Validate widths, unicast address, memory bounds, and depth-one limits.
    pub fn validate(self) -> Result<(), ConnectionInfoError> {
        let invalid = |field| Err(ConnectionInfoError::Field(field));
        if self.ipv4[0] == 0 || self.ipv4[0] >= 224 {
            return invalid("ipv4");
        }
        if !(2..=0x00ff_ffff).contains(&self.qpn) {
            return invalid("qpn");
        }
        if self.psn > 0x00ff_ffff {
            return invalid("psn");
        }
        if PathMtu::from_bytes(usize::from(self.mtu)).is_none() {
            return invalid("mtu");
        }
        if self
            .remote_address
            .checked_add(self.remote_length)
            .is_none()
        {
            return invalid("remote range");
        }
        if self.retry_count > 7
            || self.rnr_retry_count > 7
            || self.timeout > 31
            || self.rnr_nak_timer > 31
        {
            return invalid("retry policy");
        }
        if self.max_rd_atomic != 1 || self.max_dest_rd_atomic != 1 {
            return invalid("READ depth");
        }
        if self.udp_source_port < 49_152 {
            return invalid("UDP source port");
        }
        Ok(())
    }

    /// Encode a fixed-size version-one record without allocation.
    pub fn encode(self) -> Result<[u8; RC_CONNECTION_INFO_LEN], ConnectionInfoError> {
        self.validate()?;
        let mut out = [0; RC_CONNECTION_INFO_LEN];
        out[..4].copy_from_slice(b"RCV2");
        out[4..6].copy_from_slice(&1_u16.to_be_bytes());
        out[6..8].copy_from_slice(&64_u16.to_be_bytes());
        out[8..12].copy_from_slice(&self.ipv4);
        out[12..18].copy_from_slice(&self.mac);
        out[18..20].copy_from_slice(&self.mtu.to_be_bytes());
        out[20..24].copy_from_slice(&self.qpn.to_be_bytes());
        out[24..28].copy_from_slice(&self.psn.to_be_bytes());
        out[28..32].copy_from_slice(&self.rkey.to_be_bytes());
        out[32..40].copy_from_slice(&self.remote_address.to_be_bytes());
        out[40..48].copy_from_slice(&self.remote_length.to_be_bytes());
        out[48..54].copy_from_slice(&[
            self.retry_count,
            self.rnr_retry_count,
            self.timeout,
            self.max_rd_atomic,
            self.max_dest_rd_atomic,
            self.rnr_nak_timer,
        ]);
        out[54..56].copy_from_slice(&self.udp_source_port.to_be_bytes());
        Ok(out)
    }

    /// Decode one exact version-one record; truncated or extended input is rejected.
    pub fn decode(input: &[u8]) -> Result<Self, ConnectionInfoError> {
        let bytes: &[u8; RC_CONNECTION_INFO_LEN] =
            input.try_into().map_err(|_| ConnectionInfoError::Length)?;
        if &bytes[..4] != b"RCV2" || bytes[4..6] != [0, 1] {
            return Err(ConnectionInfoError::Version);
        }
        if bytes[6..8] != [0, 64] {
            return Err(ConnectionInfoError::Length);
        }
        if bytes[56..].iter().any(|&byte| byte != 0) {
            return Err(ConnectionInfoError::Reserved);
        }
        // Fixed-width copies avoid alignment assumptions and pointer casts.
        let word = |offset| u32::from_be_bytes(core::array::from_fn(|i| bytes[offset + i]));
        let wide = |offset| u64::from_be_bytes(core::array::from_fn(|i| bytes[offset + i]));
        let info = Self {
            ipv4: core::array::from_fn(|i| bytes[8 + i]),
            mac: core::array::from_fn(|i| bytes[12 + i]),
            mtu: u16::from_be_bytes([bytes[18], bytes[19]]),
            qpn: word(20),
            psn: word(24),
            rkey: word(28),
            remote_address: wide(32),
            remote_length: wide(40),
            retry_count: bytes[48],
            rnr_retry_count: bytes[49],
            timeout: bytes[50],
            max_rd_atomic: bytes[51],
            max_dest_rd_atomic: bytes[52],
            rnr_nak_timer: bytes[53],
            udp_source_port: u16::from_be_bytes([bytes[54], bytes[55]]),
        };
        info.validate()?;
        Ok(info)
    }

    /// Build local QP configuration after validating both peers and choosing the smaller MTU.
    pub fn qp_config(self, remote: Self) -> Result<RcQpConfig, ConnectionInfoError> {
        self.validate()?;
        remote.validate()?;
        let path_mtu = PathMtu::from_bytes(usize::from(self.mtu.min(remote.mtu)))
            .ok_or(ConnectionInfoError::Field("mtu"))?;
        Ok(RcQpConfig {
            transport: QpConfig {
                local_qpn: self.qpn,
                remote_qpn: remote.qpn,
                send_psn: Psn::new_truncated(self.psn),
                receive_psn: Psn::new_truncated(remote.psn),
                path_mtu,
                retry_count: self.retry_count,
                rnr_retry_count: self.rnr_retry_count,
                timeout: self.timeout,
            },
            path: Ipv4Path::new(self.ipv4, remote.ipv4, self.udp_source_port),
            rnr_nak_timer: self.rnr_nak_timer,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> RcConnectionInfo {
        RcConnectionInfo {
            ipv4: [192, 0, 2, 2],
            mac: [0; 6],
            qpn: 2,
            psn: 0x00ff_fff0,
            mtu: 256,
            rkey: 0x1234_5678,
            remote_address: 0x0102_0304_0506_0708,
            remote_length: 4096,
            retry_count: 6,
            rnr_retry_count: 6,
            timeout: 14,
            max_rd_atomic: 1,
            max_dest_rd_atomic: 1,
            rnr_nak_timer: 1,
            udp_source_port: 49_152,
        }
    }

    #[test]
    fn stable_layout_roundtrips_and_rejects_truncation() {
        let expected = info();
        let encoded = expected.encode().unwrap();
        assert_eq!(&encoded[..8], b"RCV2\0\x01\0\x40");
        assert_eq!(&encoded[32..40], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(RcConnectionInfo::decode(&encoded), Ok(expected));
        for length in 0..64 {
            assert_eq!(
                RcConnectionInfo::decode(&encoded[..length]),
                Err(ConnectionInfoError::Length)
            );
        }
        for offset in 56..64 {
            let mut damaged = encoded;
            damaged[offset] = 1;
            assert_eq!(
                RcConnectionInfo::decode(&damaged),
                Err(ConnectionInfoError::Reserved)
            );
        }
        let mut invalid = expected;
        invalid.psn = 1 << 24;
        assert!(invalid.encode().is_err());
        invalid = expected;
        invalid.remote_address = u64::MAX;
        assert!(invalid.encode().is_err());
        invalid = expected;
        invalid.max_rd_atomic = 2;
        assert!(invalid.encode().is_err());
    }
}
