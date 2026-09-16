//! Fixed-capacity endpoint composition over a packet backend.

use crate::{
    ApiError, DecodedPacket, Ipv4Path, MIN_ROCE_IPV4_PACKET, PollError, QpHandle,
    decode_ipv4_packet, encode_ipv4_packet,
};
use rocev2_core::{
    AckAdvance, Psn, QpConfig, QpState, QpStateMachine, ReceiveDisposition, ReceivePsn, SendWindow,
};
use rocev2_io::PacketIo;
use rocev2_wire::{Opcode, PacketSpec};

/// Endpoint-wide limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointConfig {
    /// Maximum complete IPv4 packet accepted or transmitted.
    pub maximum_packet_size: usize,
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self {
            maximum_packet_size: usize::from(u16::MAX),
        }
    }
}

/// Cumulative endpoint counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EndpointStats {
    /// Successfully decoded receive packets.
    pub receive_packets: u64,
    /// Successfully decoded receive bytes.
    pub receive_bytes: u64,
    /// Successfully transmitted packets.
    pub transmit_packets: u64,
    /// Successfully transmitted bytes.
    pub transmit_bytes: u64,
    /// Packets rejected during complete IPv4/UDP/transport validation.
    pub invalid_packets: u64,
    /// Valid packets whose destination QPN was not present.
    pub unknown_qp_packets: u64,
    /// Valid packets delivered while the matching QP could not receive.
    pub qp_not_ready_packets: u64,
    /// Packet backend failures.
    pub io_errors: u64,
}

/// Result of one nonblocking receive poll.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PollProgress {
    /// The backend had no packet ready.
    Idle,
    /// One packet passed wire validation and QP routing checks.
    Packet {
        /// Complete IPv4 packet byte length.
        bytes: usize,
        /// BTH destination queue-pair number.
        destination_qpn: u32,
        /// Decoded RC opcode.
        opcode: Opcode,
    },
}

#[derive(Clone, Copy, Debug)]
struct QpSlot {
    generation: u32,
    machine: QpStateMachine,
    send_window: SendWindow,
    receive_psn: ReceivePsn,
}

/// A fixed-capacity RoCEv2 endpoint over a caller-selected packet backend.
///
/// This type provides strict complete-packet I/O, queue-pair lifecycle,
/// packet-sequence bookkeeping, and QP routing. It does not yet execute posted
/// SEND/READ/WRITE work requests; that executor is deliberately kept separate
/// from these already testable protocol foundations.
pub struct Endpoint<Io, const QPS: usize = 1024> {
    io: Io,
    config: EndpointConfig,
    stats: EndpointStats,
    qps: [Option<QpSlot>; QPS],
    generations: [u32; QPS],
}

impl<Io, const QPS: usize> Endpoint<Io, QPS>
where
    Io: PacketIo,
{
    /// Compose an endpoint over `io` after validating packet limits.
    pub fn new(io: Io, config: EndpointConfig) -> Result<Self, ApiError> {
        if config.maximum_packet_size < MIN_ROCE_IPV4_PACKET {
            return Err(ApiError::BufferTooShort {
                needed: MIN_ROCE_IPV4_PACKET,
                actual: config.maximum_packet_size,
            });
        }

        let backend_maximum = io.max_ipv4_packet();
        if config.maximum_packet_size > backend_maximum {
            return Err(ApiError::UnsupportedMaximumPacket {
                requested: config.maximum_packet_size,
                backend: backend_maximum,
            });
        }

        Ok(Self {
            io,
            config,
            stats: EndpointStats::default(),
            qps: core::array::from_fn(|_| None),
            generations: [0; QPS],
        })
    }

    /// Return endpoint configuration.
    #[must_use]
    pub const fn config(&self) -> EndpointConfig {
        self.config
    }

    /// Return a snapshot of cumulative counters.
    #[must_use]
    pub const fn stats(&self) -> EndpointStats {
        self.stats
    }

    /// Borrow the packet backend.
    #[must_use]
    pub const fn io(&self) -> &Io {
        &self.io
    }

    /// Mutably borrow the packet backend.
    pub fn io_mut(&mut self) -> &mut Io {
        &mut self.io
    }

    /// Consume the endpoint and return the packet backend.
    pub fn into_io(self) -> Io {
        self.io
    }

    /// Create a validated queue pair in RESET state.
    pub fn create_qp(&mut self, config: QpConfig) -> Result<QpHandle, ApiError> {
        if self
            .qps
            .iter()
            .flatten()
            .any(|slot| slot.machine.config().local_qpn == config.local_qpn)
        {
            return Err(ApiError::DuplicateLocalQpn(config.local_qpn));
        }

        let machine = QpStateMachine::new(config)?;
        let index = self
            .qps
            .iter()
            .position(Option::is_none)
            .ok_or(ApiError::QpTableFull)?;
        let generation = self.generations[index].wrapping_add(1).max(1);
        self.generations[index] = generation;
        self.qps[index] = Some(QpSlot {
            generation,
            machine,
            send_window: SendWindow::new(config.send_psn),
            receive_psn: ReceivePsn::new(config.receive_psn),
        });

        let slot = u32::try_from(index).map_err(|_| ApiError::QpTableFull)?;
        Ok(QpHandle::new(slot, generation))
    }

    /// Remove a queue pair and invalidate its handle.
    pub fn remove_qp(&mut self, handle: QpHandle) -> Result<QpConfig, ApiError> {
        let index = self.qp_index(handle)?;
        let slot = self.qps[index].take().ok_or(ApiError::InvalidQpHandle)?;
        Ok(slot.machine.config())
    }

    /// Return the current state for a live queue pair.
    pub fn qp_state(&self, handle: QpHandle) -> Result<QpState, ApiError> {
        Ok(self.qp_slot(handle)?.machine.state())
    }

    /// Return the configuration for a live queue pair.
    pub fn qp_config(&self, handle: QpHandle) -> Result<QpConfig, ApiError> {
        Ok(self.qp_slot(handle)?.machine.config())
    }

    /// Apply a validated queue-pair state transition.
    pub fn transition_qp(
        &mut self,
        handle: QpHandle,
        destination: QpState,
    ) -> Result<(), ApiError> {
        let slot = self.qp_slot_mut(handle)?;
        slot.machine.transition(destination)?;
        if matches!(destination, QpState::Reset) {
            let config = slot.machine.config();
            slot.send_window.reset(config.send_psn);
            slot.receive_psn.reset(config.receive_psn);
        }
        Ok(())
    }

    /// Replace queue-pair configuration while it remains in RESET.
    pub fn reconfigure_qp(&mut self, handle: QpHandle, config: QpConfig) -> Result<(), ApiError> {
        if self.qps.iter().flatten().any(|slot| {
            slot.machine.config().local_qpn == config.local_qpn
                && slot.generation != handle.generation()
        }) {
            return Err(ApiError::DuplicateLocalQpn(config.local_qpn));
        }

        let slot = self.qp_slot_mut(handle)?;
        slot.machine.reconfigure(config)?;
        slot.send_window.reset(config.send_psn);
        slot.receive_psn.reset(config.receive_psn);
        Ok(())
    }

    /// Reserve the next requester PSN, respecting the unambiguous send window.
    pub fn reserve_send_psn(&mut self, handle: QpHandle) -> Result<Option<Psn>, ApiError> {
        let slot = self.qp_slot_mut(handle)?;
        if !slot.machine.can_send() {
            return Err(ApiError::QpNotReady(slot.machine.state()));
        }
        Ok(slot.send_window.reserve())
    }

    /// Apply a cumulative ACK to a queue pair's requester send window.
    pub fn acknowledge_send(
        &mut self,
        handle: QpHandle,
        acknowledged: Psn,
    ) -> Result<AckAdvance, ApiError> {
        Ok(self
            .qp_slot_mut(handle)?
            .send_window
            .acknowledge(acknowledged))
    }

    /// Classify and consume one incoming requester PSN.
    pub fn observe_receive_psn(
        &mut self,
        handle: QpHandle,
        received: Psn,
    ) -> Result<ReceiveDisposition, ApiError> {
        let slot = self.qp_slot_mut(handle)?;
        if !slot.machine.can_receive() {
            return Err(ApiError::QpNotReady(slot.machine.state()));
        }
        Ok(slot.receive_psn.observe(received))
    }

    /// Encode and transmit one complete RoCEv2 packet.
    pub fn transmit(
        &mut self,
        path: Ipv4Path,
        packet: PacketSpec<'_>,
        scratch: &mut [u8],
    ) -> Result<usize, PollError<Io::Error>> {
        let length = encode_ipv4_packet(path, packet, scratch)?;
        if length > self.config.maximum_packet_size {
            return Err(ApiError::PacketTooLarge {
                length,
                maximum: self.config.maximum_packet_size,
            }
            .into());
        }

        if let Err(error) = self.io.transmit_ipv4(&scratch[..length]) {
            self.stats.io_errors = self.stats.io_errors.saturating_add(1);
            return Err(PollError::Io(error));
        }
        self.stats.transmit_packets = self.stats.transmit_packets.saturating_add(1);
        self.stats.transmit_bytes = self
            .stats
            .transmit_bytes
            .saturating_add(u64::try_from(length).unwrap_or(u64::MAX));
        Ok(length)
    }

    /// Receive and strictly decode one complete packet without QP routing.
    pub fn receive<'buffer>(
        &mut self,
        scratch: &'buffer mut [u8],
    ) -> Result<Option<DecodedPacket<'buffer>>, PollError<Io::Error>> {
        if scratch.len() < self.config.maximum_packet_size {
            return Err(ApiError::BufferTooShort {
                needed: self.config.maximum_packet_size,
                actual: scratch.len(),
            }
            .into());
        }

        let length = match self.io.receive_ipv4(scratch) {
            Ok(Some(length)) => length,
            Ok(None) => return Ok(None),
            Err(error) => {
                self.stats.io_errors = self.stats.io_errors.saturating_add(1);
                return Err(PollError::Io(error));
            }
        };
        if length > self.config.maximum_packet_size || length > scratch.len() {
            self.stats.invalid_packets = self.stats.invalid_packets.saturating_add(1);
            return Err(ApiError::PacketTooLarge {
                length,
                maximum: self.config.maximum_packet_size.min(scratch.len()),
            }
            .into());
        }

        let decoded = match decode_ipv4_packet(&scratch[..length]) {
            Ok(decoded) => decoded,
            Err(error) => {
                self.stats.invalid_packets = self.stats.invalid_packets.saturating_add(1);
                return Err(PollError::Api(error));
            }
        };
        self.stats.receive_packets = self.stats.receive_packets.saturating_add(1);
        self.stats.receive_bytes = self
            .stats
            .receive_bytes
            .saturating_add(u64::try_from(length).unwrap_or(u64::MAX));
        Ok(Some(decoded))
    }

    /// Poll one packet and validate that a ready QP owns its destination QPN.
    pub fn poll_receive(
        &mut self,
        scratch: &mut [u8],
    ) -> Result<PollProgress, PollError<Io::Error>> {
        let Some(decoded) = self.receive(scratch)? else {
            return Ok(PollProgress::Idle);
        };

        let destination_qpn = decoded.transport.bth.destination_qpn;
        let opcode = decoded.transport.bth.opcode;
        let bytes = usize::from(decoded.ipv4.total_length);
        let Some(slot) = self
            .qps
            .iter()
            .flatten()
            .find(|slot| slot.machine.config().local_qpn == destination_qpn)
        else {
            self.stats.unknown_qp_packets = self.stats.unknown_qp_packets.saturating_add(1);
            return Err(ApiError::UnknownDestinationQpn(destination_qpn).into());
        };
        if !slot.machine.can_receive() {
            let state = slot.machine.state();
            self.stats.qp_not_ready_packets = self.stats.qp_not_ready_packets.saturating_add(1);
            return Err(ApiError::QpNotReady(state).into());
        }

        Ok(PollProgress::Packet {
            bytes,
            destination_qpn,
            opcode,
        })
    }

    fn qp_index(&self, handle: QpHandle) -> Result<usize, ApiError> {
        let index = usize::try_from(handle.slot()).map_err(|_| ApiError::InvalidQpHandle)?;
        let slot = self
            .qps
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(ApiError::InvalidQpHandle)?;
        if slot.generation != handle.generation() {
            return Err(ApiError::InvalidQpHandle);
        }
        Ok(index)
    }

    fn qp_slot(&self, handle: QpHandle) -> Result<&QpSlot, ApiError> {
        let index = self.qp_index(handle)?;
        self.qps[index].as_ref().ok_or(ApiError::InvalidQpHandle)
    }

    fn qp_slot_mut(&mut self, handle: QpHandle) -> Result<&mut QpSlot, ApiError> {
        let index = self.qp_index(handle)?;
        self.qps[index].as_mut().ok_or(ApiError::InvalidQpHandle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocev2_core::PathMtu;
    use rocev2_io::MockIo;
    use rocev2_wire::Bth;

    fn qp_config(local_qpn: u32) -> QpConfig {
        QpConfig {
            local_qpn,
            remote_qpn: 3,
            send_psn: Psn::new_truncated(5),
            receive_psn: Psn::new_truncated(7),
            path_mtu: PathMtu::Mtu1024,
            retry_count: 3,
            rnr_retry_count: 3,
            timeout: 14,
        }
    }

    fn endpoint() -> Endpoint<MockIo, 2> {
        Endpoint::new(
            MockIo::new(1500),
            EndpointConfig {
                maximum_packet_size: 1500,
            },
        )
        .unwrap()
    }

    #[test]
    fn qp_handles_are_generation_checked() {
        let mut endpoint = endpoint();
        let first = endpoint.create_qp(qp_config(2)).unwrap();
        endpoint.remove_qp(first).unwrap();
        let second = endpoint.create_qp(qp_config(2)).unwrap();

        assert_ne!(first, second);
        assert_eq!(endpoint.qp_state(first), Err(ApiError::InvalidQpHandle));
        assert_eq!(endpoint.qp_state(second), Ok(QpState::Reset));
    }

    #[test]
    fn qp_lifecycle_and_psn_tracking_are_composed() {
        let mut endpoint = endpoint();
        let handle = endpoint.create_qp(qp_config(2)).unwrap();
        endpoint.transition_qp(handle, QpState::Init).unwrap();
        endpoint.transition_qp(handle, QpState::Rtr).unwrap();
        endpoint.transition_qp(handle, QpState::Rts).unwrap();

        assert_eq!(endpoint.reserve_send_psn(handle).unwrap(), Psn::new(5));
        assert_eq!(
            endpoint.observe_receive_psn(handle, Psn::new_truncated(7)),
            Ok(ReceiveDisposition::Expected)
        );
    }

    #[test]
    fn transmits_and_routes_a_strictly_validated_packet() {
        let mut endpoint = endpoint();
        let handle = endpoint.create_qp(qp_config(2)).unwrap();
        endpoint.transition_qp(handle, QpState::Init).unwrap();
        endpoint.transition_qp(handle, QpState::Rtr).unwrap();

        let path = Ipv4Path::new([192, 0, 2, 1], [192, 0, 2, 2], 49_152);
        let packet = PacketSpec {
            bth: Bth::new(Opcode::SendOnly, 2, 7),
            reth: None,
            aeth: None,
            immediate_data: None,
            payload: b"hello",
        };
        let mut scratch = [0_u8; 1500];
        endpoint.transmit(path, packet, &mut scratch).unwrap();
        let frame = endpoint.io_mut().pop_transmitted().unwrap();
        endpoint.io_mut().inject_receive(frame.as_bytes()).unwrap();

        assert!(matches!(
            endpoint.poll_receive(&mut scratch).unwrap(),
            PollProgress::Packet {
                destination_qpn: 2,
                opcode: Opcode::SendOnly,
                ..
            }
        ));
        assert_eq!(endpoint.stats().transmit_packets, 1);
        assert_eq!(endpoint.stats().receive_packets, 1);
    }

    #[test]
    fn rejects_duplicate_local_qpn() {
        let mut endpoint = endpoint();
        endpoint.create_qp(qp_config(2)).unwrap();
        assert_eq!(
            endpoint.create_qp(qp_config(2)),
            Err(ApiError::DuplicateLocalQpn(2))
        );
    }
}
