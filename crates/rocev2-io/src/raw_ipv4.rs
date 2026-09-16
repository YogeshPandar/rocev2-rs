//! Linux raw-IPv4 reference backend.

use crate::PacketIo;
use rocev2_wire::{IP_PROTOCOL_UDP, IPV4_HEADER_LEN};
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// Configuration for a nonblocking Linux raw IPv4 socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawIpv4Config {
    /// Local address passed to `bind(2)`, or `0.0.0.0` for all local addresses.
    pub bind_address: Ipv4Addr,
    /// Largest complete IPv4 packet accepted by the backend.
    pub max_ipv4_packet: usize,
}

impl Default for RawIpv4Config {
    fn default() -> Self {
        Self {
            bind_address: Ipv4Addr::UNSPECIFIED,
            max_ipv4_packet: usize::from(u16::MAX),
        }
    }
}

/// Nonblocking Linux `AF_INET/SOCK_RAW/IPPROTO_UDP` packet backend.
///
/// Creating the socket normally requires `CAP_NET_RAW` (or equivalent
/// privilege). Transmit packets must already contain a complete IPv4 header;
/// `IP_HDRINCL` is enabled during construction.
#[derive(Debug)]
pub struct RawIpv4Socket {
    descriptor: OwnedFd,
    config: RawIpv4Config,
}

impl RawIpv4Socket {
    /// Create, configure, and bind a raw IPv4 socket.
    pub fn bind(config: RawIpv4Config) -> io::Result<Self> {
        validate_maximum(config.max_ipv4_packet)?;

        // SAFETY: socket has no pointer arguments. A successful descriptor is
        // immediately wrapped in OwnedFd exactly once.
        let raw_descriptor = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                libc::IPPROTO_UDP,
            )
        };
        if raw_descriptor < 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: raw_descriptor is newly owned after a successful socket call.
        let descriptor = unsafe { OwnedFd::from_raw_fd(raw_descriptor) };
        let enabled: libc::c_int = 1;
        let option_length = libc::socklen_t::try_from(core::mem::size_of_val(&enabled))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "sockopt size overflow"))?;

        // SAFETY: the option pointer references a live c_int for option_length
        // bytes, and the descriptor is valid and owned.
        let option_result = unsafe {
            libc::setsockopt(
                descriptor.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                (&enabled as *const libc::c_int).cast(),
                option_length,
            )
        };
        if option_result != 0 {
            return Err(io::Error::last_os_error());
        }

        let local = socket_address(config.bind_address);
        let address_length = libc::socklen_t::try_from(core::mem::size_of_val(&local))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "sockaddr size overflow"))?;

        // SAFETY: local is a fully initialized sockaddr_in and the pointer and
        // byte count describe that value exactly.
        let bind_result = unsafe {
            libc::bind(
                descriptor.as_raw_fd(),
                (&local as *const libc::sockaddr_in).cast(),
                address_length,
            )
        };
        if bind_result != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { descriptor, config })
    }

    /// Return the local address supplied at construction.
    #[must_use]
    pub const fn bind_address(&self) -> Ipv4Addr {
        self.config.bind_address
    }
}

impl PacketIo for RawIpv4Socket {
    type Error = io::Error;

    fn max_ipv4_packet(&self) -> usize {
        self.config.max_ipv4_packet
    }

    fn transmit_ipv4(&mut self, packet: &[u8]) -> Result<(), Self::Error> {
        let destination = validate_outgoing_packet(packet, self.config.max_ipv4_packet)?;
        let remote = socket_address(destination);
        let address_length = libc::socklen_t::try_from(core::mem::size_of_val(&remote))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "sockaddr size overflow"))?;

        // SAFETY: packet and remote both remain live for the call and their
        // lengths are exact. The descriptor is valid and owned.
        let sent = unsafe {
            libc::sendto(
                self.descriptor.as_raw_fd(),
                packet.as_ptr().cast(),
                packet.len(),
                0,
                (&remote as *const libc::sockaddr_in).cast(),
                address_length,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        let sent = usize::try_from(sent)
            .map_err(|_| io::Error::other("sendto returned a negative-compatible length"))?;
        if sent != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "raw socket transmitted a partial IPv4 datagram",
            ));
        }
        Ok(())
    }

    fn receive_ipv4(&mut self, output: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        if output.len() < self.config.max_ipv4_packet {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "receive buffer is smaller than configured maximum packet",
            ));
        }

        // SAFETY: output is live and writable for output.len() bytes. MSG_TRUNC
        // asks Linux to report the original datagram length if truncation ever
        // occurs despite the configured maximum.
        let received = unsafe {
            libc::recv(
                self.descriptor.as_raw_fd(),
                output.as_mut_ptr().cast(),
                output.len(),
                libc::MSG_TRUNC,
            )
        };
        if received < 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.raw_os_error(),
                Some(code) if code == libc::EAGAIN || code == libc::EWOULDBLOCK
            ) {
                return Ok(None);
            }
            return Err(error);
        }

        let received = usize::try_from(received)
            .map_err(|_| io::Error::other("recv returned a negative-compatible length"))?;
        if received > output.len() || received > self.config.max_ipv4_packet {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "received IPv4 datagram exceeds configured maximum",
            ));
        }
        Ok(Some(received))
    }
}

fn validate_maximum(maximum: usize) -> io::Result<()> {
    if !(IPV4_HEADER_LEN..=usize::from(u16::MAX)).contains(&maximum) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "maximum IPv4 packet must be between 20 and 65535 bytes",
        ));
    }
    Ok(())
}

fn validate_outgoing_packet(packet: &[u8], maximum: usize) -> io::Result<Ipv4Addr> {
    if packet.len() > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "IPv4 packet exceeds configured maximum",
        ));
    }
    if packet.len() < IPV4_HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "truncated IPv4 header",
        ));
    }
    if packet[0] >> 4 != 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "packet is not IPv4",
        ));
    }

    let header_length = usize::from(packet[0] & 0x0f) * 4;
    if header_length < IPV4_HEADER_LEN || header_length > packet.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid IPv4 header length",
        ));
    }
    let total_length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_length != packet.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "IPv4 total length does not match packet length",
        ));
    }
    if packet[9] != IP_PROTOCOL_UDP {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "RoCEv2 raw backend accepts UDP IPv4 packets only",
        ));
    }

    Ok(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ))
}

fn socket_address(address: Ipv4Addr) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::sa_family_t::try_from(libc::AF_INET).unwrap_or_default(),
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(address.octets()),
        },
        sin_zero: [0; 8],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_packet() -> [u8; IPV4_HEADER_LEN] {
        let mut packet = [0_u8; IPV4_HEADER_LEN];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(IPV4_HEADER_LEN as u16).to_be_bytes());
        packet[9] = IP_PROTOCOL_UDP;
        packet[16..20].copy_from_slice(&[192, 0, 2, 1]);
        packet
    }

    #[test]
    fn validates_complete_ipv4_packet_without_opening_socket() {
        let packet = valid_packet();
        assert_eq!(
            validate_outgoing_packet(&packet, 1500).unwrap(),
            Ipv4Addr::new(192, 0, 2, 1)
        );
    }

    #[test]
    fn rejects_mismatched_total_length() {
        let mut packet = valid_packet();
        packet[3] = 19;
        assert_eq!(
            validate_outgoing_packet(&packet, 1500).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn validates_configured_maximum() {
        assert!(validate_maximum(19).is_err());
        assert!(validate_maximum(20).is_ok());
        assert!(validate_maximum(usize::from(u16::MAX)).is_ok());
    }
}
