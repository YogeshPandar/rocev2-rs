//! deterministic allocation-free packet fault injection.

use crate::PacketIo;
use core::fmt;
use rocev2_wire::{
    IP_PROTOCOL_UDP, IPV4_HEADER_LEN, Ipv4Header, Opcode, PacketRef, ParseOptions,
    ROCE_V2_UDP_PORT, UDP_HEADER_LEN, UdpHeader,
};

/// packet direction observed by the fault wrapper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultDirection {
    /// packet received from the wrapped backend.
    Receive,
    /// packet submitted to the wrapped backend.
    Transmit,
}

/// deterministic packet fault action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultAction {
    /// consume the packet without forwarding it.
    Drop,
    /// forward the packet twice.
    Duplicate,
    /// defer the packet until the next operation in the same direction.
    Delay,
    /// swap the packet with the next packet in the same direction.
    Reorder,
    /// flip one bit in the final byte, normally invalidating the ICRC.
    Corrupt,
}

/// one fixed matching rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultRule {
    action: FaultAction,
    direction: FaultDirection,
    packet_number: Option<u64>,
    opcode: Option<Opcode>,
    qpn: Option<u32>,
    psn: Option<u32>,
    remaining: u32,
}

impl FaultRule {
    /// create a one-shot rule for one direction.
    #[must_use]
    pub const fn new(action: FaultAction, direction: FaultDirection) -> Self {
        Self {
            action,
            direction,
            packet_number: None,
            opcode: None,
            qpn: None,
            psn: None,
            remaining: 1,
        }
    }

    /// match one one-based packet number for the selected direction.
    #[must_use]
    pub const fn packet_number(mut self, packet_number: u64) -> Self {
        self.packet_number = Some(packet_number);
        self
    }

    /// match one transport opcode.
    #[must_use]
    pub const fn opcode(mut self, opcode: Opcode) -> Self {
        self.opcode = Some(opcode);
        self
    }

    /// match one destination queue-pair number.
    #[must_use]
    pub const fn qpn(mut self, qpn: u32) -> Self {
        self.qpn = Some(qpn & 0x00ff_ffff);
        self
    }

    /// match one 24-bit packet sequence number.
    #[must_use]
    pub const fn psn(mut self, psn: u32) -> Self {
        self.psn = Some(psn & 0x00ff_ffff);
        self
    }

    /// apply the rule this many times before removing it.
    #[must_use]
    pub const fn times(mut self, count: u32) -> Self {
        self.remaining = count;
        self
    }

    fn matches(
        self,
        direction: FaultDirection,
        packet_number: u64,
        identity: Option<PacketIdentity>,
    ) -> bool {
        if self.remaining == 0 || self.direction != direction {
            return false;
        }
        if self
            .packet_number
            .is_some_and(|value| value != packet_number)
        {
            return false;
        }
        if self.opcode.is_none() && self.qpn.is_none() && self.psn.is_none() {
            return true;
        }
        let Some(identity) = identity else {
            return false;
        };
        self.opcode.is_none_or(|value| value == identity.opcode)
            && self.qpn.is_none_or(|value| value == identity.qpn)
            && self.psn.is_none_or(|value| value == identity.psn)
    }
}

/// cumulative deterministic fault counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FaultStatistics {
    /// packets intentionally dropped.
    pub dropped: u64,
    /// packets intentionally duplicated.
    pub duplicated: u64,
    /// packets intentionally delayed.
    pub delayed: u64,
    /// adjacent packet pairs intentionally reordered.
    pub reordered: u64,
    /// packets intentionally corrupted.
    pub corrupted: u64,
}

/// fault-rule configuration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultRuleError {
    /// fixed fault rule table is full.
    TableFull,
    /// a rule cannot be configured to run zero times.
    ZeroCount,
}

impl fmt::Display for FaultRuleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TableFull => formatter.write_str("fault rule table is full"),
            Self::ZeroCount => formatter.write_str("fault rule count must be nonzero"),
        }
    }
}

impl core::error::Error for FaultRuleError {}

/// fault-wrapper failure.
#[derive(Debug)]
pub enum FaultInjectError<E> {
    /// wrapped backend failure.
    Inner(E),
    /// packet exceeds the wrapper's fixed packet storage.
    PacketTooLarge {
        /// observed packet length.
        length: usize,
        /// wrapper packet capacity.
        maximum: usize,
    },
    /// caller receive storage is too small.
    OutputTooSmall {
        /// required packet length.
        required: usize,
        /// caller buffer length.
        available: usize,
    },
}

impl<E: fmt::Display> fmt::Display for FaultInjectError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inner(error) => write!(formatter, "wrapped packet I/O failed: {error}"),
            Self::PacketTooLarge { length, maximum } => {
                write!(
                    formatter,
                    "packet length {length} exceeds fault buffer {maximum}"
                )
            }
            Self::OutputTooSmall {
                required,
                available,
            } => write!(
                formatter,
                "receive buffer length {available} is smaller than fault packet {required}"
            ),
        }
    }
}

impl<E> core::error::Error for FaultInjectError<E>
where
    E: core::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Inner(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PacketIdentity {
    opcode: Opcode,
    qpn: u32,
    psn: u32,
}

#[derive(Debug)]
struct BufferedPacket<const MAX_PACKET: usize> {
    bytes: [u8; MAX_PACKET],
    length: usize,
    ready: bool,
}

impl<const MAX_PACKET: usize> BufferedPacket<MAX_PACKET> {
    const fn new() -> Self {
        Self {
            bytes: [0; MAX_PACKET],
            length: 0,
            ready: false,
        }
    }

    fn store<E>(&mut self, packet: &[u8]) -> Result<(), FaultInjectError<E>> {
        if packet.len() > MAX_PACKET {
            return Err(FaultInjectError::PacketTooLarge {
                length: packet.len(),
                maximum: MAX_PACKET,
            });
        }
        self.bytes[..packet.len()].copy_from_slice(packet);
        self.length = packet.len();
        self.ready = true;
        Ok(())
    }

    fn copy_to<E>(&mut self, output: &mut [u8]) -> Result<usize, FaultInjectError<E>> {
        if output.len() < self.length {
            return Err(FaultInjectError::OutputTooSmall {
                required: self.length,
                available: output.len(),
            });
        }
        let length = self.length;
        output[..length].copy_from_slice(&self.bytes[..length]);
        self.ready = false;
        self.length = 0;
        Ok(length)
    }
}

/// fixed-capacity deterministic fault wrapper for scalar packet I/O.
///
/// no heap allocation occurs in construction or packet processing. delayed,
/// duplicated, and reordered packets use one fixed packet slot per direction.
#[derive(Debug)]
pub struct FaultInjectIo<I, const RULES: usize, const MAX_PACKET: usize> {
    inner: I,
    rules: [Option<FaultRule>; RULES],
    tx_packet_number: u64,
    rx_packet_number: u64,
    tx_held: BufferedPacket<MAX_PACKET>,
    rx_held: BufferedPacket<MAX_PACKET>,
    tx_reorder_waiting: bool,
    rx_reorder_waiting: bool,
    tx_scratch: [u8; MAX_PACKET],
    rx_scratch: [u8; MAX_PACKET],
    statistics: FaultStatistics,
}

impl<I, const RULES: usize, const MAX_PACKET: usize> FaultInjectIo<I, RULES, MAX_PACKET> {
    /// wrap one backend with an empty rule table.
    #[must_use]
    pub fn new(inner: I) -> Self {
        Self {
            inner,
            rules: core::array::from_fn(|_| None),
            tx_packet_number: 0,
            rx_packet_number: 0,
            tx_held: BufferedPacket::new(),
            rx_held: BufferedPacket::new(),
            tx_reorder_waiting: false,
            rx_reorder_waiting: false,
            tx_scratch: [0; MAX_PACKET],
            rx_scratch: [0; MAX_PACKET],
            statistics: FaultStatistics::default(),
        }
    }

    /// borrow the wrapped backend.
    #[must_use]
    pub const fn inner(&self) -> &I {
        &self.inner
    }

    /// mutably borrow the wrapped backend.
    pub fn inner_mut(&mut self) -> &mut I {
        &mut self.inner
    }

    /// consume the wrapper and return the backend.
    pub fn into_inner(self) -> I {
        self.inner
    }

    /// return fault counters.
    #[must_use]
    pub const fn statistics(&self) -> FaultStatistics {
        self.statistics
    }

    /// install one rule in the first free fixed slot.
    pub fn push_rule(&mut self, rule: FaultRule) -> Result<(), FaultRuleError> {
        if rule.remaining == 0 {
            return Err(FaultRuleError::ZeroCount);
        }
        let Some(slot) = self.rules.iter_mut().find(|slot| slot.is_none()) else {
            return Err(FaultRuleError::TableFull);
        };
        *slot = Some(rule);
        Ok(())
    }

    /// remove all configured rules without changing packet counters.
    pub fn clear_rules(&mut self) {
        self.rules.fill(None);
    }

    fn take_action(
        &mut self,
        direction: FaultDirection,
        packet_number: u64,
        identity: Option<PacketIdentity>,
    ) -> Option<FaultAction> {
        for slot in &mut self.rules {
            let Some(rule) = *slot else {
                continue;
            };
            if !rule.matches(direction, packet_number, identity) {
                continue;
            }
            let action = rule.action;
            let remaining = rule.remaining - 1;
            *slot = if remaining == 0 {
                None
            } else {
                Some(FaultRule { remaining, ..rule })
            };
            return Some(action);
        }
        None
    }

    fn count_action(&mut self, action: FaultAction) {
        let counter = match action {
            FaultAction::Drop => &mut self.statistics.dropped,
            FaultAction::Duplicate => &mut self.statistics.duplicated,
            FaultAction::Delay => &mut self.statistics.delayed,
            FaultAction::Reorder => &mut self.statistics.reordered,
            FaultAction::Corrupt => &mut self.statistics.corrupted,
        };
        *counter = counter.saturating_add(1);
    }
}

impl<I, const RULES: usize, const MAX_PACKET: usize> PacketIo
    for FaultInjectIo<I, RULES, MAX_PACKET>
where
    I: PacketIo,
{
    type Error = FaultInjectError<I::Error>;

    fn max_ipv4_packet(&self) -> usize {
        self.inner.max_ipv4_packet().min(MAX_PACKET)
    }

    fn transmit_ipv4(&mut self, packet: &[u8]) -> Result<(), Self::Error> {
        if packet.len() > self.max_ipv4_packet() {
            return Err(FaultInjectError::PacketTooLarge {
                length: packet.len(),
                maximum: self.max_ipv4_packet(),
            });
        }

        if self.tx_reorder_waiting {
            self.tx_packet_number = self.tx_packet_number.saturating_add(1);
            self.inner
                .transmit_ipv4(packet)
                .map_err(FaultInjectError::Inner)?;
            self.inner
                .transmit_ipv4(&self.tx_held.bytes[..self.tx_held.length])
                .map_err(FaultInjectError::Inner)?;
            self.tx_held.ready = false;
            self.tx_held.length = 0;
            self.tx_reorder_waiting = false;
            return Ok(());
        }

        if self.tx_held.ready {
            self.inner
                .transmit_ipv4(&self.tx_held.bytes[..self.tx_held.length])
                .map_err(FaultInjectError::Inner)?;
            self.tx_held.ready = false;
            self.tx_held.length = 0;
        }

        self.tx_packet_number = self.tx_packet_number.saturating_add(1);
        let identity = packet_identity(packet);
        let action = self.take_action(FaultDirection::Transmit, self.tx_packet_number, identity);
        let Some(action) = action else {
            return self
                .inner
                .transmit_ipv4(packet)
                .map_err(FaultInjectError::Inner);
        };
        self.count_action(action);

        match action {
            FaultAction::Drop => Ok(()),
            FaultAction::Duplicate => {
                self.inner
                    .transmit_ipv4(packet)
                    .map_err(FaultInjectError::Inner)?;
                self.inner
                    .transmit_ipv4(packet)
                    .map_err(FaultInjectError::Inner)
            }
            FaultAction::Delay => self.tx_held.store(packet),
            FaultAction::Reorder => {
                self.tx_held.store(packet)?;
                self.tx_reorder_waiting = true;
                Ok(())
            }
            FaultAction::Corrupt => {
                self.tx_scratch[..packet.len()].copy_from_slice(packet);
                if let Some(last) = self.tx_scratch[..packet.len()].last_mut() {
                    *last ^= 1;
                }
                self.inner
                    .transmit_ipv4(&self.tx_scratch[..packet.len()])
                    .map_err(FaultInjectError::Inner)
            }
        }
    }

    fn receive_ipv4(&mut self, output: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        if self.rx_reorder_waiting {
            if let Some(length) = self
                .inner
                .receive_ipv4(&mut self.rx_scratch)
                .map_err(FaultInjectError::Inner)?
            {
                self.rx_packet_number = self.rx_packet_number.saturating_add(1);
                if length > MAX_PACKET {
                    return Err(FaultInjectError::PacketTooLarge {
                        length,
                        maximum: MAX_PACKET,
                    });
                }
                if output.len() < length {
                    return Err(FaultInjectError::OutputTooSmall {
                        required: length,
                        available: output.len(),
                    });
                }
                output[..length].copy_from_slice(&self.rx_scratch[..length]);
                self.rx_reorder_waiting = false;
                return Ok(Some(length));
            }
            self.rx_reorder_waiting = false;
            return self.rx_held.copy_to(output).map(Some);
        }

        if self.rx_held.ready {
            return self.rx_held.copy_to(output).map(Some);
        }

        let Some(length) = self
            .inner
            .receive_ipv4(&mut self.rx_scratch)
            .map_err(FaultInjectError::Inner)?
        else {
            return Ok(None);
        };
        if length > MAX_PACKET {
            return Err(FaultInjectError::PacketTooLarge {
                length,
                maximum: MAX_PACKET,
            });
        }

        self.rx_packet_number = self.rx_packet_number.saturating_add(1);
        let identity = packet_identity(&self.rx_scratch[..length]);
        let action = self.take_action(FaultDirection::Receive, self.rx_packet_number, identity);
        let Some(action) = action else {
            if output.len() < length {
                return Err(FaultInjectError::OutputTooSmall {
                    required: length,
                    available: output.len(),
                });
            }
            output[..length].copy_from_slice(&self.rx_scratch[..length]);
            return Ok(Some(length));
        };
        self.count_action(action);
        let packet = &self.rx_scratch[..length];

        match action {
            FaultAction::Drop => Ok(None),
            FaultAction::Duplicate => {
                self.rx_held.store(packet)?;
                if output.len() < length {
                    return Err(FaultInjectError::OutputTooSmall {
                        required: length,
                        available: output.len(),
                    });
                }
                output[..length].copy_from_slice(packet);
                Ok(Some(length))
            }
            FaultAction::Delay => {
                self.rx_held.store(packet)?;
                Ok(None)
            }
            FaultAction::Reorder => {
                self.rx_held.store(packet)?;
                self.rx_reorder_waiting = true;
                Ok(None)
            }
            FaultAction::Corrupt => {
                if output.len() < length {
                    return Err(FaultInjectError::OutputTooSmall {
                        required: length,
                        available: output.len(),
                    });
                }
                output[..length].copy_from_slice(packet);
                if let Some(last) = output[..length].last_mut() {
                    *last ^= 1;
                }
                Ok(Some(length))
            }
        }
    }
}

fn packet_identity(packet: &[u8]) -> Option<PacketIdentity> {
    let ipv4 = Ipv4Header::decode(packet).ok()?;
    if ipv4.protocol != IP_PROTOCOL_UDP
        || usize::from(ipv4.total_length) != packet.len()
        || packet.len() < IPV4_HEADER_LEN + UDP_HEADER_LEN
    {
        return None;
    }

    let udp_start = IPV4_HEADER_LEN;
    let transport_start = udp_start + UDP_HEADER_LEN;
    let udp = UdpHeader::decode(&packet[udp_start..]).ok()?;
    if udp.destination_port != ROCE_V2_UDP_PORT
        || usize::from(udp.length) != packet.len() - IPV4_HEADER_LEN
    {
        return None;
    }
    let transport = PacketRef::parse(&packet[transport_start..], ParseOptions::STRICT).ok()?;
    Some(PacketIdentity {
        opcode: transport.bth.opcode,
        qpn: transport.bth.destination_qpn,
        psn: transport.bth.psn & 0x00ff_ffff,
    })
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::MockIo;
    use rocev2_wire::{Bth, PacketSpec};

    fn packet(opcode: Opcode, qpn: u32, psn: u32) -> [u8; 44] {
        let mut output = [0; 44];
        let mut ip = [0; IPV4_HEADER_LEN];
        let mut udp = [0; UDP_HEADER_LEN];
        Ipv4Header::udp([192, 0, 2, 1], [192, 0, 2, 2], 44)
            .encode(&mut ip)
            .unwrap();
        UdpHeader {
            source_port: 49_152,
            destination_port: ROCE_V2_UDP_PORT,
            length: 24,
            checksum: 0,
        }
        .encode(&mut udp)
        .unwrap();
        output[..IPV4_HEADER_LEN].copy_from_slice(&ip);
        output[IPV4_HEADER_LEN..IPV4_HEADER_LEN + UDP_HEADER_LEN].copy_from_slice(&udp);
        PacketSpec {
            bth: Bth::new(opcode, qpn, psn),
            reth: None,
            aeth: None,
            immediate_data: None,
            payload: &[],
        }
        .encode_with_icrc(&ip, &udp, &mut output[IPV4_HEADER_LEN + UDP_HEADER_LEN..])
        .unwrap();
        output
    }

    #[test]
    fn transmit_rules_match_packet_fields_without_allocation() {
        let inner = MockIo::new(64);
        let mut io = FaultInjectIo::<_, 4, 64>::new(inner);
        io.push_rule(
            FaultRule::new(FaultAction::Drop, FaultDirection::Transmit)
                .opcode(Opcode::SendOnly)
                .qpn(7)
                .psn(9),
        )
        .unwrap();
        io.transmit_ipv4(&packet(Opcode::SendOnly, 7, 9)).unwrap();
        assert_eq!(io.inner().pending_transmit(), 0);
        assert_eq!(io.statistics().dropped, 1);
    }

    #[test]
    fn duplicate_and_delay_are_one_shot_and_preserve_order() {
        let first = packet(Opcode::SendOnly, 7, 1);
        let second = packet(Opcode::SendOnly, 7, 2);
        let mut inner = MockIo::new(64);
        inner.inject_receive(&first).unwrap();
        inner.inject_receive(&second).unwrap();
        let mut io = FaultInjectIo::<_, 4, 64>::new(inner);
        io.push_rule(
            FaultRule::new(FaultAction::Duplicate, FaultDirection::Receive).packet_number(1),
        )
        .unwrap();

        let mut output = [0; 64];
        assert_eq!(io.receive_ipv4(&mut output).unwrap(), Some(44));
        assert_eq!(packet_identity(&output[..44]).unwrap().psn, 1);
        assert_eq!(io.receive_ipv4(&mut output).unwrap(), Some(44));
        assert_eq!(packet_identity(&output[..44]).unwrap().psn, 1);
        assert_eq!(io.receive_ipv4(&mut output).unwrap(), Some(44));
        assert_eq!(packet_identity(&output[..44]).unwrap().psn, 2);
        assert_eq!(io.statistics().duplicated, 1);

        io.inner_mut().inject_receive(&first).unwrap();
        io.push_rule(FaultRule::new(FaultAction::Delay, FaultDirection::Receive).packet_number(3))
            .unwrap();
        assert_eq!(io.receive_ipv4(&mut output).unwrap(), None);
        assert_eq!(io.receive_ipv4(&mut output).unwrap(), Some(44));
        assert_eq!(packet_identity(&output[..44]).unwrap().psn, 1);
        assert_eq!(io.statistics().delayed, 1);
    }

    #[test]
    fn repeated_rule_exhausts_and_masks_wire_widths() {
        let inner = MockIo::new(64);
        let mut io = FaultInjectIo::<_, 2, 64>::new(inner);
        io.push_rule(
            FaultRule::new(FaultAction::Drop, FaultDirection::Transmit)
                .qpn(0xff00_0007)
                .psn(0xab00_0009)
                .times(2),
        )
        .unwrap();

        let target = packet(Opcode::SendOnly, 7, 9);
        io.transmit_ipv4(&target).unwrap();
        io.transmit_ipv4(&target).unwrap();
        io.transmit_ipv4(&target).unwrap();
        assert_eq!(io.statistics().dropped, 2);
        assert_eq!(io.inner().pending_transmit(), 1);
    }

    #[test]
    fn receive_duplicate_delay_reorder_and_corrupt_are_deterministic() {
        let mut inner = MockIo::new(64);
        let first = packet(Opcode::SendOnly, 7, 1);
        let second = packet(Opcode::SendOnly, 7, 2);
        inner.inject_receive(&first).unwrap();
        inner.inject_receive(&second).unwrap();

        let mut io = FaultInjectIo::<_, 4, 64>::new(inner);
        io.push_rule(
            FaultRule::new(FaultAction::Reorder, FaultDirection::Receive).packet_number(1),
        )
        .unwrap();
        let mut output = [0; 64];
        assert_eq!(io.receive_ipv4(&mut output).unwrap(), None);
        assert_eq!(io.receive_ipv4(&mut output).unwrap(), Some(44));
        assert_eq!(packet_identity(&output[..44]).unwrap().psn, 2);
        assert_eq!(io.receive_ipv4(&mut output).unwrap(), Some(44));
        assert_eq!(packet_identity(&output[..44]).unwrap().psn, 1);

        io.inner_mut().inject_receive(&first).unwrap();
        io.push_rule(
            FaultRule::new(FaultAction::Corrupt, FaultDirection::Receive).packet_number(3),
        )
        .unwrap();
        assert_eq!(io.receive_ipv4(&mut output).unwrap(), Some(44));
        assert_ne!(&output[..44], &first);
        assert_eq!(io.statistics().reordered, 1);
        assert_eq!(io.statistics().corrupted, 1);
    }
}
