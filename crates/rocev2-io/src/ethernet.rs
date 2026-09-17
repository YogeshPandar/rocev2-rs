//! ethernet framing for packet backends that operate below ipv4.

use rocev2_wire::IPV4_HEADER_LEN;

/// ethernet ii header length without vlan tags.
pub const ETHERNET_HEADER_LEN: usize = 14;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88a8;

/// fixed layer-2 path used by an ethernet packet backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EthernetPath {
    source_mac: [u8; 6],
    destination_mac: [u8; 6],
}

impl EthernetPath {
    /// create a path with explicit source and destination mac addresses.
    #[must_use]
    pub const fn new(source_mac: [u8; 6], destination_mac: [u8; 6]) -> Self {
        Self {
            source_mac,
            destination_mac,
        }
    }

    /// return the source mac address.
    #[must_use]
    pub const fn source_mac(self) -> [u8; 6] {
        self.source_mac
    }

    /// return the destination mac address.
    #[must_use]
    pub const fn destination_mac(self) -> [u8; 6] {
        self.destination_mac
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EthernetFrameError {
    Truncated,
    VlanUnsupported,
    NonIpv4,
    InvalidIpv4,
}

pub(crate) fn write_ipv4_header(header: &mut [u8; ETHERNET_HEADER_LEN], path: EthernetPath) {
    header[..6].copy_from_slice(&path.destination_mac);
    header[6..12].copy_from_slice(&path.source_mac);
    header[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
}

pub(crate) fn ipv4_payload(frame: &[u8]) -> Result<&[u8], EthernetFrameError> {
    if frame.len() < ETHERNET_HEADER_LEN + IPV4_HEADER_LEN {
        return Err(EthernetFrameError::Truncated);
    }

    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if matches!(ethertype, ETHERTYPE_VLAN | ETHERTYPE_QINQ) {
        return Err(EthernetFrameError::VlanUnsupported);
    }
    if ethertype != ETHERTYPE_IPV4 {
        return Err(EthernetFrameError::NonIpv4);
    }

    let ipv4 = &frame[ETHERNET_HEADER_LEN..];
    if ipv4[0] >> 4 != 4 {
        return Err(EthernetFrameError::InvalidIpv4);
    }
    let header_length = usize::from(ipv4[0] & 0x0f) * 4;
    if header_length < IPV4_HEADER_LEN || header_length > ipv4.len() {
        return Err(EthernetFrameError::InvalidIpv4);
    }

    let total_length = usize::from(u16::from_be_bytes([ipv4[2], ipv4[3]]));
    if total_length < header_length || total_length > ipv4.len() {
        return Err(EthernetFrameError::InvalidIpv4);
    }

    Ok(&ipv4[..total_length])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_packet() -> [u8; IPV4_HEADER_LEN] {
        let mut packet = [0_u8; IPV4_HEADER_LEN];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(IPV4_HEADER_LEN as u16).to_be_bytes());
        packet
    }

    #[test]
    fn writes_and_parses_untagged_ipv4() {
        let path = EthernetPath::new([1, 2, 3, 4, 5, 6], [6, 5, 4, 3, 2, 1]);
        let packet = ipv4_packet();
        let mut frame = [0_u8; ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + 8];
        write_ipv4_header(
            (&mut frame[..ETHERNET_HEADER_LEN]).try_into().unwrap(),
            path,
        );
        frame[ETHERNET_HEADER_LEN..ETHERNET_HEADER_LEN + packet.len()].copy_from_slice(&packet);

        assert_eq!(&frame[..6], &path.destination_mac());
        assert_eq!(&frame[6..12], &path.source_mac());
        assert_eq!(ipv4_payload(&frame).unwrap(), packet);
    }

    #[test]
    fn rejects_vlan_and_qinq() {
        for ethertype in [ETHERTYPE_VLAN, ETHERTYPE_QINQ] {
            let mut frame = [0_u8; ETHERNET_HEADER_LEN + IPV4_HEADER_LEN];
            frame[12..14].copy_from_slice(&ethertype.to_be_bytes());
            assert_eq!(
                ipv4_payload(&frame),
                Err(EthernetFrameError::VlanUnsupported)
            );
        }
    }

    #[test]
    fn trims_ethernet_padding_to_ipv4_total_length() {
        let path = EthernetPath::new([1; 6], [2; 6]);
        let packet = ipv4_packet();
        let mut frame = [0_u8; ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + 32];
        write_ipv4_header(
            (&mut frame[..ETHERNET_HEADER_LEN]).try_into().unwrap(),
            path,
        );
        frame[ETHERNET_HEADER_LEN..ETHERNET_HEADER_LEN + packet.len()].copy_from_slice(&packet);

        assert_eq!(ipv4_payload(&frame).unwrap().len(), IPV4_HEADER_LEN);
    }
}
