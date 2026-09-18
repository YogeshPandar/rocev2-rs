//! Posted-work Reliable Connected execution engine.
//!
//! This module turns the wire, memory, and deterministic core primitives into
//! an allocation-free steady-state transport. Heap allocation is confined to
//! endpoint and QP construction; posting, polling, parsing, memory access,
//! completion, ACK/NAK generation, and retransmission use fixed-capacity state.

use crate::qp::{insert_qpn, qpn_slot, validate_qpn_index};
use crate::{
    ApiError, DecodedPacket, Ipv4Path, MIN_ROCE_IPV4_PACKET, PollError, QpHandle, QueueKind,
    decode_ipv4_packet, encode_ipv4_packet,
};
use alloc::boxed::Box;
use rocev2_core::{
    AckAdvance, Completion, CompletionOpcode, CompletionStatus, MAX_OUTSTANDING_PACKETS, Psn,
    QpConfig, QpState, QpStateMachine, QpnTable, ReadyQueue, ReceiveDisposition, ReceivePsn,
    RecvWorkRequest, RetryBudget, RetryDecision, RetryPolicy, RetryReason, Ring, SendWindow, Timer,
    TimerEntry, TimerScheduler, WorkRequest, WorkRequestKind, ack_timeout_ticks, rnr_timer_ticks,
};
use rocev2_io::{PacketBatchIo, PacketIo, TxPacket};
use rocev2_memory::{
    AccessFlags, KeyGenerator, MemoryAccess, MemoryError, MemoryRegistry, RegionHandle, RegionLease,
};
use rocev2_wire::{
    AETH_LEN, Aeth, AethClass, BTH_LEN, Bth, ICRC_LEN, IPV4_HEADER_LEN, NakCode, Opcode, PacketRef,
    PacketSpec, RETH_LEN, Reth, SegmentPosition, UDP_HEADER_LEN,
};

const MAX_MTU_BYTES: usize = 4096;
const MAX_RNR_TIMER: u8 = 31;

/// maximum packet burst accepted by [`RcEndpoint::progress_batch`].
pub const MAX_BATCH_PACKETS: usize = 64;

/// Configuration for the posted-work RC engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RcEndpointConfig {
    /// Maximum complete IPv4 packet accepted or transmitted.
    pub maximum_packet_size: usize,
    /// Frequency of the monotonic tick value supplied to [`RcEndpoint::progress`].
    pub ticks_per_second: u64,
    /// Per-endpoint seed used to diversify lkeys and rkeys.
    pub memory_key_seed: u32,
}

impl Default for RcEndpointConfig {
    fn default() -> Self {
        Self {
            maximum_packet_size: usize::from(u16::MAX),
            ticks_per_second: 1_000_000_000,
            memory_key_seed: 0x726f_6365,
        }
    }
}

/// Connection-specific configuration for one RC QP.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RcQpConfig {
    /// Deterministic RC state-machine and PSN configuration.
    pub transport: QpConfig,
    /// Local-to-peer IPv4/UDP path used for every requester and responder packet.
    pub path: Ipv4Path,
    /// Five-bit AETH delay advertised when a SEND has no receive WQE.
    pub rnr_nak_timer: u8,
}

impl RcQpConfig {
    /// Construct a QP configuration using RNR timer code zero.
    #[must_use]
    pub const fn new(transport: QpConfig, path: Ipv4Path) -> Self {
        Self {
            transport,
            path,
            rnr_nak_timer: 0,
        }
    }
}

/// Cumulative counters for the posted-work data path.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RcEndpointStats {
    /// Strictly decoded incoming packets.
    pub receive_packets: u64,
    /// Strictly decoded incoming complete-IPv4 bytes.
    pub receive_bytes: u64,
    /// Successfully submitted outgoing packets.
    pub transmit_packets: u64,
    /// Successfully submitted outgoing complete-IPv4 bytes.
    pub transmit_bytes: u64,
    /// Packets rejected by strict IPv4/UDP/transport/ICRC validation.
    pub invalid_packets: u64,
    /// Valid packets addressed to an unknown QPN.
    pub unknown_qp_packets: u64,
    /// Valid packets received from an address other than the connected peer.
    pub peer_mismatch_packets: u64,
    /// Packet-backend failures.
    pub io_errors: u64,
    /// Send-queue work requests accepted from the application.
    pub posted_work_requests: u64,
    /// Receive WQEs accepted from the application.
    pub posted_receive_requests: u64,
    /// Completion entries generated.
    pub completions: u64,
    /// Positive ACK packets transmitted.
    pub acknowledgements: u64,
    /// Non-RNR NAK packets transmitted.
    pub negative_acknowledgements: u64,
    /// RNR NAK packets transmitted or received.
    pub rnr_naks: u64,
    /// Request operations restarted after timeout, sequence NAK, or RNR delay.
    pub retransmissions: u64,
    /// Local ACK timers that expired.
    pub timeout_events: u64,
    /// Incoming future-PSN requests that caused sequence NAKs.
    pub sequence_errors: u64,
    /// Duplicate requester packets accepted without repeating side effects.
    pub duplicate_requests: u64,
}

/// Work performed by one nonblocking engine progress call.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RcProgress {
    /// Number of incoming packets consumed; currently zero or one.
    pub received_packets: usize,
    /// Number of outgoing packets submitted; currently zero or one.
    pub transmitted_packets: usize,
    /// Number of completion entries generated.
    pub completions: usize,
    /// Number of operations moved into retransmission state.
    pub retransmissions: usize,
}

impl RcProgress {
    /// Return whether the call consumed, transmitted, completed, or rescheduled work.
    #[must_use]
    pub const fn made_progress(self) -> bool {
        self.received_packets != 0
            || self.transmitted_packets != 0
            || self.completions != 0
            || self.retransmissions != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestPhase {
    Sending,
    Waiting,
    RnrWait,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestPacketError {
    ArithmeticOverflow,
    LocalProtection,
}

#[derive(Clone, Copy, Debug)]
struct ActiveRequest {
    work: WorkRequest,
    first_psn: Psn,
    last_psn: Psn,
    packet_count: u32,
    next_packet: u32,
    transmitted_packets: u32,
    read_packets_received: u32,
    bytes_received: u32,
    retry_budget: RetryBudget,
    timer: Timer,
    phase: RequestPhase,
}

impl ActiveRequest {
    fn reset_for_retry(&mut self) {
        self.next_packet = 0;
        self.read_packets_received = 0;
        self.bytes_received = 0;
        self.phase = RequestPhase::Sending;
        self.timer.cancel();
    }

    const fn completion_opcode(self) -> CompletionOpcode {
        match self.work.kind {
            WorkRequestKind::Send => CompletionOpcode::Send,
            WorkRequestKind::RdmaWrite { .. } => CompletionOpcode::RdmaWrite,
            WorkRequestKind::RdmaRead { .. } => CompletionOpcode::RdmaRead,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum InboundMessage {
    Send {
        work: RecvWorkRequest,
        bytes_written: u32,
    },
    Write {
        address: u64,
        rkey: u32,
        total_length: u32,
        bytes_written: u32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReadResponseState {
    request_psn: Psn,
    address: u64,
    rkey: u32,
    length: u32,
    packet_count: u32,
    next_packet: u32,
}

#[derive(Debug)]
struct PostedWork<T> {
    work: T,
    lease: Option<RegionLease>,
}

fn release_lease<const MRS: usize>(
    memory: &mut MemoryRegistry<'_, MRS>,
    lease: &mut Option<RegionLease>,
) {
    let result = memory.release(lease);
    debug_assert!(
        result.is_ok(),
        "endpoint owns only leases from its registry"
    );
}

fn retain_batch<const MRS: usize, const B: usize>(
    memory: &mut MemoryRegistry<'_, MRS>,
    keys: impl Iterator<Item = u32>,
) -> Result<[Option<RegionLease>; B], ApiError> {
    let mut leases = core::array::from_fn(|_| None);
    for (index, key) in keys.enumerate() {
        match memory.retain_local(key) {
            Ok(lease) => leases[index] = Some(lease),
            Err(error) => {
                for lease in &mut leases {
                    release_lease(memory, lease);
                }
                return Err(error.into());
            }
        }
    }
    Ok(leases)
}

#[derive(Debug)]
struct RcQpSlot<const SQ: usize, const RQ: usize, const CQ: usize> {
    generation: u32,
    machine: QpStateMachine,
    path: Ipv4Path,
    rnr_nak_timer: u8,
    send_window: SendWindow,
    receive_psn: ReceivePsn,
    send_queue: Ring<PostedWork<WorkRequest>, SQ>,
    receive_queue: Ring<PostedWork<RecvWorkRequest>, RQ>,
    completion_queue: Ring<Completion, CQ>,
    completion_reservations: usize,
    active_request: Option<ActiveRequest>,
    active_memory: Option<RegionLease>,
    inbound_memory: Option<RegionLease>,
    read_memory: Option<RegionLease>,
    inbound_message: Option<InboundMessage>,
    read_response: Option<ReadResponseState>,
    read_replay: Option<ReadResponseState>,
    message_sequence_number: Psn,
    requester_scheduled: bool,
    responder_scheduled: bool,
    timer_sequence: u32,
}

impl<const SQ: usize, const RQ: usize, const CQ: usize> RcQpSlot<SQ, RQ, CQ> {
    fn new(generation: u32, config: RcQpConfig) -> Result<Self, ApiError> {
        Ok(Self {
            generation,
            machine: QpStateMachine::new(config.transport)?,
            path: config.path,
            rnr_nak_timer: config.rnr_nak_timer,
            send_window: SendWindow::new(config.transport.send_psn),
            receive_psn: ReceivePsn::new(config.transport.receive_psn),
            send_queue: Ring::new(),
            receive_queue: Ring::new(),
            completion_queue: Ring::new(),
            completion_reservations: 0,
            active_request: None,
            active_memory: None,
            inbound_memory: None,
            read_memory: None,
            inbound_message: None,
            read_response: None,
            read_replay: None,
            message_sequence_number: Psn::ZERO,
            requester_scheduled: false,
            responder_scheduled: false,
            timer_sequence: 0,
        })
    }

    const fn config(&self) -> RcQpConfig {
        RcQpConfig {
            transport: self.machine.config(),
            path: self.path,
            rnr_nak_timer: self.rnr_nak_timer,
        }
    }

    fn can_reserve_completion(&self) -> bool {
        self.completion_queue
            .len()
            .saturating_add(self.completion_reservations)
            < CQ
    }

    fn reserve_completion(&mut self) -> Result<(), ApiError> {
        if !self.can_reserve_completion() {
            return Err(ApiError::QueueFull(QueueKind::Completion));
        }
        self.completion_reservations += 1;
        Ok(())
    }

    fn resolve_reserved_completion(&mut self, completion: Option<Completion>) -> usize {
        debug_assert!(self.completion_reservations != 0);
        self.completion_reservations = self.completion_reservations.saturating_sub(1);
        if let Some(completion) = completion {
            self.completion_queue
                .push(completion)
                .expect("a reserved completion slot must be available");
            1
        } else {
            0
        }
    }

    fn finish_active<const MRS: usize>(
        &mut self,
        memory: &mut MemoryRegistry<'_, MRS>,
        status: CompletionStatus,
        byte_len: u32,
    ) -> usize {
        release_lease(memory, &mut self.active_memory);
        let Some(active) = self.active_request.take() else {
            return 0;
        };
        let completion = if active.work.signaled || !matches!(status, CompletionStatus::Success) {
            Some(if matches!(status, CompletionStatus::Success) {
                Completion::success(active.work.id, active.completion_opcode(), byte_len)
            } else {
                Completion::failure(active.work.id, active.completion_opcode(), status)
            })
        } else {
            None
        };
        self.resolve_reserved_completion(completion)
    }

    fn finish_receive<const MRS: usize>(
        &mut self,
        memory: &mut MemoryRegistry<'_, MRS>,
        work: RecvWorkRequest,
        status: CompletionStatus,
        byte_len: u32,
    ) -> usize {
        release_lease(memory, &mut self.inbound_memory);
        let completion = if matches!(status, CompletionStatus::Success) {
            Completion::success(work.id, CompletionOpcode::Receive, byte_len)
        } else {
            Completion::failure(work.id, CompletionOpcode::Receive, status)
        };
        self.resolve_reserved_completion(Some(completion))
    }

    fn flush_pending<const MRS: usize>(&mut self, memory: &mut MemoryRegistry<'_, MRS>) -> usize {
        let mut generated = 0;
        generated += self.finish_active(memory, CompletionStatus::Flushed, 0);

        if let Some(InboundMessage::Send { work, .. }) = self.inbound_message.take() {
            generated += self.finish_receive(memory, work, CompletionStatus::Flushed, 0);
        } else {
            self.inbound_message = None;
        }
        release_lease(memory, &mut self.inbound_memory);
        release_lease(memory, &mut self.read_memory);
        self.read_response = None;
        self.read_replay = None;

        while let Some(mut posted) = self.send_queue.pop() {
            release_lease(memory, &mut posted.lease);
            let work = posted.work;
            let opcode = match work.kind {
                WorkRequestKind::Send => CompletionOpcode::Send,
                WorkRequestKind::RdmaWrite { .. } => CompletionOpcode::RdmaWrite,
                WorkRequestKind::RdmaRead { .. } => CompletionOpcode::RdmaRead,
            };
            generated += self.resolve_reserved_completion(Some(Completion::failure(
                work.id,
                opcode,
                CompletionStatus::Flushed,
            )));
        }
        while let Some(mut posted) = self.receive_queue.pop() {
            release_lease(memory, &mut posted.lease);
            generated += self.finish_receive(memory, posted.work, CompletionStatus::Flushed, 0);
        }
        generated
    }

    fn enter_error<const MRS: usize>(&mut self, memory: &mut MemoryRegistry<'_, MRS>) -> usize {
        if !matches!(self.machine.state(), QpState::Error) {
            let transition = self.machine.transition(QpState::Error);
            debug_assert!(transition.is_ok());
        }
        self.flush_pending(memory)
    }

    fn is_busy(&self) -> bool {
        self.active_request.is_some()
            || self.inbound_message.is_some()
            || self.read_response.is_some()
            || !self.send_queue.is_empty()
            || !self.receive_queue.is_empty()
            || !self.completion_queue.is_empty()
            || self.completion_reservations != 0
            || self.requester_scheduled
            || self.responder_scheduled
    }

    fn requester_is_runnable(&self) -> bool {
        match self.active_request {
            Some(active) => matches!(active.phase, RequestPhase::Sending),
            None => self.machine.can_send() && !self.send_queue.is_empty(),
        }
    }

    fn responder_is_runnable(&self) -> bool {
        self.machine.can_receive() && self.read_response.is_some()
    }

    fn timer_deadline(&self) -> Option<u64> {
        let active = self.active_request?;
        match active.phase {
            RequestPhase::Waiting | RequestPhase::RnrWait => active.timer.deadline(),
            RequestPhase::Sending => None,
        }
    }

    fn reset_transport_state(&mut self) {
        let config = self.machine.config();
        self.send_window.reset(config.send_psn);
        self.receive_psn.reset(config.receive_psn);
        self.message_sequence_number = Psn::ZERO;
        self.active_request = None;
        self.inbound_message = None;
        self.read_response = None;
        self.read_replay = None;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ControlReply {
    path: Ipv4Path,
    destination_qpn: u32,
    psn: Psn,
    aeth: Aeth,
}

#[derive(Clone, Copy, Debug, Default)]
struct HandlerResult {
    reply: Option<ControlReply>,
    completions: usize,
    retransmissions: usize,
}

#[derive(Clone, Copy, Debug)]
struct ReadyReadResponse {
    qp_index: usize,
    path: Ipv4Path,
    remote_qpn: u32,
    response: ReadResponseState,
    message_sequence_number: Psn,
    mtu: usize,
}

#[derive(Clone, Copy, Debug)]
struct PreparedWirePacket {
    path: Ipv4Path,
    bth: Bth,
    reth: Option<Reth>,
    aeth: Option<Aeth>,
    payload_length: usize,
}

#[derive(Clone, Copy, Debug)]
enum PreparedTx {
    Control(ControlReply),
    Requester {
        qp_index: usize,
        timeout_ticks: u64,
        next_class: DataTxClass,
    },
    Responder {
        qp_index: usize,
        next_class: DataTxClass,
    },
}

impl PreparedTx {
    const fn qp_index(self) -> Option<usize> {
        match self {
            Self::Control(_) => None,
            Self::Requester { qp_index, .. } | Self::Responder { qp_index, .. } => Some(qp_index),
        }
    }
}

struct BatchTxBuffers<F> {
    frames: [Option<F>; MAX_BATCH_PACKETS],
    packets: [TxPacket<F>; MAX_BATCH_PACKETS],
    metadata: [Option<PreparedTx>; MAX_BATCH_PACKETS],
}

impl<F> Default for BatchTxBuffers<F> {
    fn default() -> Self {
        Self {
            frames: core::array::from_fn(|_| None),
            packets: core::array::from_fn(|_| TxPacket::empty()),
            metadata: [None; MAX_BATCH_PACKETS],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DataTxClass {
    Requester,
    Responder,
}

impl DataTxClass {
    const fn other(self) -> Self {
        match self {
            Self::Requester => Self::Responder,
            Self::Responder => Self::Requester,
        }
    }
}

/// Fixed-capacity posted-work RC endpoint.
///
/// QP state and queues are allocated only during control-plane QP creation.
/// Once QPs and memory are registered, [`Self::progress`], posting, completion
/// polling, ACK/NAK handling, and retransmission perform no transport-owned
/// heap allocation.
///
/// `QPN_INDEX` must be a power of two and at least twice `QPS`. The default
/// keeps the fixed open-addressed QPN table at or below 50 percent load.
pub struct RcEndpoint<
    'memory,
    Io,
    const QPS: usize = 1024,
    const MRS: usize = 4096,
    const SQ: usize = 128,
    const RQ: usize = 128,
    const CQ: usize = 256,
    const QPN_INDEX: usize = 2048,
> {
    io: Io,
    config: RcEndpointConfig,
    stats: RcEndpointStats,
    memory: Box<MemoryRegistry<'memory, MRS>>,
    qps: [Option<Box<RcQpSlot<SQ, RQ, CQ>>>; QPS],
    generations: [u32; QPS],
    qpn_index: Box<QpnTable<QPN_INDEX>>,
    payload_scratch: [u8; MAX_MTU_BYTES],
    requester_ready: ReadyQueue<QPS>,
    responder_ready: ReadyQueue<QPS>,
    timer_scheduler: TimerScheduler<QPS>,
    pending_control: Ring<ControlReply, MAX_BATCH_PACKETS>,
    next_data_tx_class: DataTxClass,
}

impl<
    'memory,
    Io,
    const QPS: usize,
    const MRS: usize,
    const SQ: usize,
    const RQ: usize,
    const CQ: usize,
    const QPN_INDEX: usize,
> RcEndpoint<'memory, Io, QPS, MRS, SQ, RQ, CQ, QPN_INDEX>
where
    Io: PacketIo,
{
    /// Construct an empty RC endpoint over `io`.
    pub fn new(io: Io, config: RcEndpointConfig) -> Result<Self, ApiError> {
        if config.maximum_packet_size < MIN_ROCE_IPV4_PACKET {
            return Err(ApiError::BufferTooShort {
                needed: MIN_ROCE_IPV4_PACKET,
                actual: config.maximum_packet_size,
            });
        }
        if config.maximum_packet_size > io.max_ipv4_packet() {
            return Err(ApiError::UnsupportedMaximumPacket {
                requested: config.maximum_packet_size,
                backend: io.max_ipv4_packet(),
            });
        }
        if config.ticks_per_second == 0 {
            return Err(ApiError::InvalidTicksPerSecond);
        }
        validate_qpn_index::<QPS, QPN_INDEX>()?;

        Ok(Self {
            io,
            config,
            stats: RcEndpointStats::default(),
            memory: Box::new(MemoryRegistry::new(config.memory_key_seed)?),
            qps: core::array::from_fn(|_| None),
            generations: [0; QPS],
            qpn_index: Box::new(QpnTable::new()),
            payload_scratch: [0; MAX_MTU_BYTES],
            requester_ready: ReadyQueue::new(),
            responder_ready: ReadyQueue::new(),
            timer_scheduler: TimerScheduler::new(),
            pending_control: Ring::new(),
            next_data_tx_class: DataTxClass::Responder,
        })
    }

    /// Return endpoint configuration.
    #[must_use]
    pub const fn config(&self) -> RcEndpointConfig {
        self.config
    }

    /// Return a snapshot of cumulative data-path counters.
    #[must_use]
    pub const fn stats(&self) -> RcEndpointStats {
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

    /// Consume the endpoint and return its packet backend.
    pub fn into_io(self) -> Io {
        self.io
    }

    /// Borrow the checked registered-memory table.
    #[must_use]
    pub fn memory_registry(&self) -> &MemoryRegistry<'memory, MRS> {
        &self.memory
    }

    /// Borrow checked copy operations without allowing registry replacement.
    pub fn memory_registry_mut(&mut self) -> MemoryAccess<'_, 'memory, MRS> {
        self.memory.access()
    }

    /// Register an exclusive application buffer.
    pub fn register_memory(
        &mut self,
        memory: &'memory mut [u8],
        access: AccessFlags,
    ) -> Result<RegionHandle, ApiError> {
        Ok(self.memory.register(memory, access)?)
    }

    /// Register with an external production key source instead of the development seed.
    pub fn register_memory_with_key_generator(
        &mut self,
        memory: &'memory mut [u8],
        access: AccessFlags,
        generator: &mut impl KeyGenerator,
    ) -> Result<RegionHandle, ApiError> {
        Ok(self
            .memory
            .register_with_key_generator(memory, access, generator)?)
    }

    /// Remove a memory registration and return its original exclusive slice.
    ///
    /// Returns `MemoryError::RegionBusy` while posted or active work references
    /// the region. Success, failure, and QP flush release references exactly once.
    pub fn deregister_memory(
        &mut self,
        handle: RegionHandle,
    ) -> Result<&'memory mut [u8], ApiError> {
        Ok(self.memory.deregister(handle)?)
    }

    /// Create a validated QP in RESET state.
    pub fn create_qp(&mut self, config: RcQpConfig) -> Result<QpHandle, ApiError> {
        if config.rnr_nak_timer > MAX_RNR_TIMER {
            return Err(ApiError::InvalidRnrNakTimer(config.rnr_nak_timer));
        }
        if self.qpn_index.get(config.transport.local_qpn).is_some() {
            return Err(ApiError::DuplicateLocalQpn(config.transport.local_qpn));
        }

        let required = maximum_packet_for_mtu(config.transport.path_mtu.bytes())?;
        if required > self.config.maximum_packet_size {
            return Err(ApiError::PathMtuExceedsPacketLimit {
                required,
                maximum: self.config.maximum_packet_size,
            });
        }

        let index = self
            .qps
            .iter()
            .position(Option::is_none)
            .ok_or(ApiError::QpTableFull)?;
        let generation = self.generations[index].wrapping_add(1).max(1);
        let slot = RcQpSlot::new(generation, config)?;
        let slot_number = insert_qpn(&mut self.qpn_index, config.transport.local_qpn, index)?;
        self.generations[index] = generation;
        self.qps[index] = Some(Box::new(slot));

        Ok(QpHandle::new(slot_number, generation))
    }

    /// Remove an idle QP and invalidate its generation-checked handle.
    pub fn remove_qp(&mut self, handle: QpHandle) -> Result<RcQpConfig, ApiError> {
        let index = self.qp_index(handle)?;
        let slot = self.qps[index].as_ref().ok_or(ApiError::InvalidQpHandle)?;
        if slot.is_busy() {
            return Err(ApiError::QpBusy);
        }
        self.deschedule_qp(index);
        let slot = self.qps[index].take().ok_or(ApiError::InvalidQpHandle)?;
        let config = slot.config();
        let removed = self.qpn_index.remove(config.transport.local_qpn);
        debug_assert_eq!(removed, Some(handle.slot()));
        Ok(config)
    }

    /// Return the current QP state.
    pub fn qp_state(&self, handle: QpHandle) -> Result<QpState, ApiError> {
        Ok(self.qp_slot(handle)?.machine.state())
    }

    /// Return the active QP configuration.
    pub fn qp_config(&self, handle: QpHandle) -> Result<RcQpConfig, ApiError> {
        Ok(self.qp_slot(handle)?.config())
    }

    /// Replace QP configuration while the QP is reset and idle.
    pub fn reconfigure_qp(&mut self, handle: QpHandle, config: RcQpConfig) -> Result<(), ApiError> {
        if config.rnr_nak_timer > MAX_RNR_TIMER {
            return Err(ApiError::InvalidRnrNakTimer(config.rnr_nak_timer));
        }
        let required = maximum_packet_for_mtu(config.transport.path_mtu.bytes())?;
        if required > self.config.maximum_packet_size {
            return Err(ApiError::PathMtuExceedsPacketLimit {
                required,
                maximum: self.config.maximum_packet_size,
            });
        }

        let index = self.qp_index(handle)?;
        if self
            .qpn_index
            .get(config.transport.local_qpn)
            .is_some_and(|owner| owner != handle.slot())
        {
            return Err(ApiError::DuplicateLocalQpn(config.transport.local_qpn));
        }

        let slot = self.qps[index].as_ref().ok_or(ApiError::InvalidQpHandle)?;
        if slot.is_busy() {
            return Err(ApiError::QpBusy);
        }
        let previous_qpn = slot.machine.config().local_qpn;
        let mut machine = slot.machine;
        machine.reconfigure(config.transport)?;

        if previous_qpn != config.transport.local_qpn {
            insert_qpn(&mut self.qpn_index, config.transport.local_qpn, index)?;
            let removed = self.qpn_index.remove(previous_qpn);
            debug_assert_eq!(removed, Some(handle.slot()));
        }

        let slot = self.qps[index].as_mut().ok_or(ApiError::InvalidQpHandle)?;
        slot.machine = machine;
        slot.path = config.path;
        slot.rnr_nak_timer = config.rnr_nak_timer;
        slot.reset_transport_state();
        self.synchronize_qp(index);
        Ok(())
    }

    /// Apply a QP state transition, flushing posted work on RESET or ERROR.
    pub fn transition_qp(
        &mut self,
        handle: QpHandle,
        destination: QpState,
    ) -> Result<(), ApiError> {
        let index = self.qp_index(handle)?;
        let generated = {
            let slot = self.qps[index].as_mut().ok_or(ApiError::InvalidQpHandle)?;
            if matches!(destination, QpState::Error) {
                slot.machine.transition(destination)?;
                slot.flush_pending(&mut self.memory)
            } else if matches!(destination, QpState::Reset) {
                slot.machine.transition(destination)?;
                let completions = slot.flush_pending(&mut self.memory);
                slot.reset_transport_state();
                completions
            } else {
                slot.machine.transition(destination)?;
                0
            }
        };
        self.synchronize_qp(index);
        self.stats.completions = self
            .stats
            .completions
            .saturating_add(u64::try_from(generated).unwrap_or(u64::MAX));
        Ok(())
    }

    /// Post one SEND, RDMA WRITE, or RDMA READ work request.
    pub fn post_work(&mut self, handle: QpHandle, work: WorkRequest) -> Result<(), ApiError> {
        let index = self.qp_index(handle)?;
        let (state, mtu) = {
            let slot = self.qps[index].as_ref().ok_or(ApiError::InvalidQpHandle)?;
            (slot.machine.state(), slot.machine.config().path_mtu.bytes())
        };
        if !matches!(state, QpState::Rts) {
            return Err(ApiError::QpNotReady(state));
        }

        validate_posted_work(&self.memory, work, mtu)?;

        {
            let slot = self.qps[index].as_mut().ok_or(ApiError::InvalidQpHandle)?;
            if slot.send_queue.is_full() {
                return Err(ApiError::QueueFull(QueueKind::Send));
            }
            slot.reserve_completion()?;
            let lease = match self.memory.retain_local(work.sge.lkey) {
                Ok(lease) => Some(lease),
                Err(error) => {
                    slot.completion_reservations -= 1;
                    return Err(error.into());
                }
            };
            if let Err(error) = slot.send_queue.push(PostedWork { work, lease }) {
                let mut posted = error.into_inner();
                release_lease(&mut self.memory, &mut posted.lease);
                slot.completion_reservations = slot.completion_reservations.saturating_sub(1);
                return Err(ApiError::QueueFull(QueueKind::Send));
            }
        }
        self.synchronize_qp(index);
        self.stats.posted_work_requests = self.stats.posted_work_requests.saturating_add(1);
        Ok(())
    }

    /// Post a batch of SEND, RDMA WRITE, or RDMA READ work requests atomically.
    ///
    /// validation and capacity checks complete before any request is accepted.
    pub fn post_work_batch(
        &mut self,
        handle: QpHandle,
        works: &[WorkRequest],
    ) -> Result<usize, ApiError> {
        if works.is_empty() {
            return Ok(0);
        }
        let index = self.qp_index(handle)?;
        let (state, mtu, send_capacity, completion_capacity) = {
            let slot = self.qps[index].as_ref().ok_or(ApiError::InvalidQpHandle)?;
            (
                slot.machine.state(),
                slot.machine.config().path_mtu.bytes(),
                slot.send_queue.remaining_capacity(),
                CQ.saturating_sub(
                    slot.completion_queue
                        .len()
                        .saturating_add(slot.completion_reservations),
                ),
            )
        };
        if !matches!(state, QpState::Rts) {
            return Err(ApiError::QpNotReady(state));
        }
        if works.len() > send_capacity {
            return Err(ApiError::QueueFull(QueueKind::Send));
        }
        if works.len() > completion_capacity {
            return Err(ApiError::QueueFull(QueueKind::Completion));
        }

        for work in works {
            validate_posted_work(&self.memory, *work, mtu)?;
        }

        let leases =
            retain_batch::<MRS, SQ>(&mut self.memory, works.iter().map(|work| work.sge.lkey))?;
        let slot = self.qps[index].as_mut().ok_or(ApiError::InvalidQpHandle)?;
        slot.completion_reservations += works.len();
        for (work, lease) in works.iter().zip(leases) {
            let pushed = slot.send_queue.push(PostedWork { work: *work, lease });
            debug_assert!(pushed.is_ok());
        }
        self.synchronize_qp(index);
        self.stats.posted_work_requests = self
            .stats
            .posted_work_requests
            .saturating_add(u64::try_from(works.len()).unwrap_or(u64::MAX));
        Ok(works.len())
    }

    /// Post one receive WQE for an incoming two-sided SEND.
    pub fn post_receive(
        &mut self,
        handle: QpHandle,
        work: RecvWorkRequest,
    ) -> Result<(), ApiError> {
        let index = self.qp_index(handle)?;
        let state = self.qps[index]
            .as_ref()
            .ok_or(ApiError::InvalidQpHandle)?
            .machine
            .state();
        if !matches!(
            state,
            QpState::Rtr | QpState::Rts | QpState::Sqd | QpState::Sqe
        ) {
            return Err(ApiError::QpNotReady(state));
        }
        let length = usize::try_from(work.sge.length).map_err(|_| ApiError::ArithmeticOverflow)?;
        self.memory
            .validate_local_write(work.sge.lkey, work.sge.address, length)?;

        let slot = self.qps[index].as_mut().ok_or(ApiError::InvalidQpHandle)?;
        if slot.receive_queue.is_full() {
            return Err(ApiError::QueueFull(QueueKind::Receive));
        }
        slot.reserve_completion()?;
        let lease = match self.memory.retain_local(work.sge.lkey) {
            Ok(lease) => Some(lease),
            Err(error) => {
                slot.completion_reservations -= 1;
                return Err(error.into());
            }
        };
        if let Err(error) = slot.receive_queue.push(PostedWork { work, lease }) {
            let mut posted = error.into_inner();
            release_lease(&mut self.memory, &mut posted.lease);
            slot.completion_reservations = slot.completion_reservations.saturating_sub(1);
            return Err(ApiError::QueueFull(QueueKind::Receive));
        }
        self.stats.posted_receive_requests = self.stats.posted_receive_requests.saturating_add(1);
        Ok(())
    }

    /// Post a batch of receive WQEs atomically.
    ///
    /// validation and capacity checks complete before any receive is accepted.
    pub fn post_receive_batch(
        &mut self,
        handle: QpHandle,
        works: &[RecvWorkRequest],
    ) -> Result<usize, ApiError> {
        if works.is_empty() {
            return Ok(0);
        }
        let index = self.qp_index(handle)?;
        let (state, receive_capacity, completion_capacity) = {
            let slot = self.qps[index].as_ref().ok_or(ApiError::InvalidQpHandle)?;
            (
                slot.machine.state(),
                slot.receive_queue.remaining_capacity(),
                CQ.saturating_sub(
                    slot.completion_queue
                        .len()
                        .saturating_add(slot.completion_reservations),
                ),
            )
        };
        if !matches!(
            state,
            QpState::Rtr | QpState::Rts | QpState::Sqd | QpState::Sqe
        ) {
            return Err(ApiError::QpNotReady(state));
        }
        if works.len() > receive_capacity {
            return Err(ApiError::QueueFull(QueueKind::Receive));
        }
        if works.len() > completion_capacity {
            return Err(ApiError::QueueFull(QueueKind::Completion));
        }
        for work in works {
            let length =
                usize::try_from(work.sge.length).map_err(|_| ApiError::ArithmeticOverflow)?;
            self.memory
                .validate_local_write(work.sge.lkey, work.sge.address, length)?;
        }

        let leases =
            retain_batch::<MRS, RQ>(&mut self.memory, works.iter().map(|work| work.sge.lkey))?;
        let slot = self.qps[index].as_mut().ok_or(ApiError::InvalidQpHandle)?;
        slot.completion_reservations += works.len();
        for (work, lease) in works.iter().zip(leases) {
            let pushed = slot.receive_queue.push(PostedWork { work: *work, lease });
            debug_assert!(pushed.is_ok());
        }
        self.stats.posted_receive_requests = self
            .stats
            .posted_receive_requests
            .saturating_add(u64::try_from(works.len()).unwrap_or(u64::MAX));
        Ok(works.len())
    }

    /// Remove the oldest completion for a QP.
    pub fn poll_completion(&mut self, handle: QpHandle) -> Result<Option<Completion>, ApiError> {
        Ok(self.qp_slot_mut(handle)?.completion_queue.pop())
    }

    /// Poll up to `output.len()` completions without allocation.
    pub fn poll_completions(
        &mut self,
        handle: QpHandle,
        output: &mut [Completion],
    ) -> Result<usize, ApiError> {
        let slot = self.qp_slot_mut(handle)?;
        let mut count = 0;
        for destination in output {
            let Some(completion) = slot.completion_queue.pop() else {
                break;
            };
            *destination = completion;
            count += 1;
        }
        Ok(count)
    }

    /// Return the current number of queued completions.
    pub fn completion_len(&self, handle: QpHandle) -> Result<usize, ApiError> {
        Ok(self.qp_slot(handle)?.completion_queue.len())
    }

    /// Make one bounded, nonblocking unit of transport progress.
    ///
    /// `now` must be monotonic in the tick domain configured by
    /// [`RcEndpointConfig::ticks_per_second`]. The receive and transmit buffers
    /// must each be at least `maximum_packet_size` bytes. At most one packet is
    /// received and one packet is transmitted per call.
    pub fn progress(
        &mut self,
        now: u64,
        receive_buffer: &mut [u8],
        transmit_buffer: &mut [u8],
    ) -> Result<RcProgress, PollError<Io::Error>> {
        self.validate_poll_buffers(receive_buffer, transmit_buffer)?;
        let mut progress = RcProgress::default();

        let timer_result = self.service_timers(now, 1);
        progress.completions += timer_result.completions;
        progress.retransmissions += timer_result.retransmissions;

        if self.transmit_pending_control(transmit_buffer)? {
            progress.transmitted_packets = 1;
            return Ok(progress);
        }

        if let Some(decoded) = self.receive_one(receive_buffer)? {
            progress.received_packets = 1;
            let result = self.process_incoming(now, decoded)?;
            progress.completions += result.completions;
            progress.retransmissions += result.retransmissions;
            if let Some(reply) = result.reply {
                let queued = self.pending_control.push(reply);
                debug_assert!(queued.is_ok());
                if self.transmit_pending_control(transmit_buffer)? {
                    progress.transmitted_packets = 1;
                    return Ok(progress);
                }
            }
        }

        let data_result = self.emit_data_packet(now, transmit_buffer)?;
        progress.completions += data_result.completions;
        if data_result.transmitted {
            progress.transmitted_packets = 1;
        }
        Ok(progress)
    }

    fn emit_data_packet(
        &mut self,
        now: u64,
        output: &mut [u8],
    ) -> Result<EmitResult, PollError<Io::Error>> {
        let first_class = self.next_data_tx_class;
        let second_class = first_class.other();
        let mut result = self.emit_data_class(first_class, now, output)?;
        if result.transmitted {
            self.next_data_tx_class = second_class;
            return Ok(result);
        }

        let fallback = self.emit_data_class(second_class, now, output)?;
        result.completions = result.completions.saturating_add(fallback.completions);
        result.transmitted = fallback.transmitted;
        if fallback.transmitted {
            self.next_data_tx_class = first_class;
        }
        Ok(result)
    }

    fn emit_data_class(
        &mut self,
        class: DataTxClass,
        now: u64,
        output: &mut [u8],
    ) -> Result<EmitResult, PollError<Io::Error>> {
        match class {
            DataTxClass::Requester => self.emit_requester(now, output),
            DataTxClass::Responder => self.emit_read_response(output),
        }
    }

    fn validate_poll_buffers(
        &self,
        receive_buffer: &[u8],
        transmit_buffer: &[u8],
    ) -> Result<(), ApiError> {
        if receive_buffer.len() < self.config.maximum_packet_size {
            return Err(ApiError::BufferTooShort {
                needed: self.config.maximum_packet_size,
                actual: receive_buffer.len(),
            });
        }
        if transmit_buffer.len() < self.config.maximum_packet_size {
            return Err(ApiError::BufferTooShort {
                needed: self.config.maximum_packet_size,
                actual: transmit_buffer.len(),
            });
        }
        Ok(())
    }

    fn receive_one<'buffer>(
        &mut self,
        buffer: &'buffer mut [u8],
    ) -> Result<Option<DecodedPacket<'buffer>>, PollError<Io::Error>> {
        let length = match self.io.receive_ipv4(buffer) {
            Ok(Some(length)) => length,
            Ok(None) => return Ok(None),
            Err(error) => {
                self.stats.io_errors = self.stats.io_errors.saturating_add(1);
                return Err(PollError::Io(error));
            }
        };
        if length > self.config.maximum_packet_size || length > buffer.len() {
            self.stats.invalid_packets = self.stats.invalid_packets.saturating_add(1);
            return Err(ApiError::PacketTooLarge {
                length,
                maximum: self.config.maximum_packet_size.min(buffer.len()),
            }
            .into());
        }

        let decoded = match decode_ipv4_packet(&buffer[..length]) {
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

    fn process_incoming(
        &mut self,
        now: u64,
        decoded: DecodedPacket<'_>,
    ) -> Result<HandlerResult, ApiError> {
        let (index, result) = process_incoming_state(
            &self.qpn_index,
            &mut self.qps,
            &mut self.memory,
            &mut self.stats,
            self.config.ticks_per_second,
            now,
            decoded,
        )?;
        self.synchronize_qp(index);
        self.stats.completions = self
            .stats
            .completions
            .saturating_add(u64::try_from(result.completions).unwrap_or(u64::MAX));
        Ok(result)
    }

    fn transmit_pending_control(
        &mut self,
        output: &mut [u8],
    ) -> Result<bool, PollError<Io::Error>> {
        let Some(reply) = self.pending_control.front().copied() else {
            return Ok(false);
        };
        self.transmit_control(reply, output)?;
        let removed = self.pending_control.pop();
        debug_assert!(removed.is_some());
        Ok(true)
    }

    fn transmit_control(
        &mut self,
        reply: ControlReply,
        output: &mut [u8],
    ) -> Result<(), PollError<Io::Error>> {
        let packet = PacketSpec {
            bth: Bth::new(
                Opcode::Acknowledge,
                reply.destination_qpn,
                reply.psn.value(),
            ),
            reth: None,
            aeth: Some(reply.aeth),
            immediate_data: None,
            payload: &[],
        };
        transmit_packet(
            &mut self.io,
            &mut self.stats,
            self.config.maximum_packet_size,
            reply.path,
            packet,
            output,
        )?;
        self.record_control_transmit(reply);
        Ok(())
    }

    fn service_timers(&mut self, now: u64, budget: usize) -> HandlerResult {
        let mut result = HandlerResult::default();
        let mut serviced = 0;

        while serviced < budget {
            let Some(entry) = self.timer_scheduler.pop_expired(now) else {
                break;
            };
            let Ok(index) = usize::try_from(entry.qp_slot()) else {
                continue;
            };
            let action = self
                .qps
                .get(index)
                .and_then(Option::as_ref)
                .and_then(|slot| {
                    if slot.generation != entry.qp_generation()
                        || slot.timer_sequence != entry.sequence()
                    {
                        return None;
                    }
                    let active = slot.active_request?;
                    if slot.timer_deadline() != Some(entry.deadline()) || !active.timer.expired(now)
                    {
                        return None;
                    }
                    Some(active.phase)
                });

            let Some(action) = action else {
                self.synchronize_qp(index);
                continue;
            };

            let Some(slot) = self.qps.get_mut(index).and_then(Option::as_mut) else {
                self.synchronize_qp(index);
                continue;
            };
            match action {
                RequestPhase::Waiting => {
                    self.stats.timeout_events = self.stats.timeout_events.saturating_add(1);
                    let retry = schedule_transport_retry(slot, &mut self.memory, &mut self.stats);
                    result.completions += retry.completions;
                    result.retransmissions += retry.retransmissions;
                }
                RequestPhase::RnrWait => {
                    if let Some(active) = slot.active_request.as_mut() {
                        active.reset_for_retry();
                        self.stats.retransmissions = self.stats.retransmissions.saturating_add(1);
                        result.retransmissions += 1;
                    }
                }
                RequestPhase::Sending => {
                    debug_assert!(false, "sending request must not retain an armed timer");
                    if let Some(active) = slot.active_request.as_mut() {
                        active.timer.cancel();
                    }
                }
            }
            self.synchronize_qp(index);
            serviced += 1;
        }

        self.stats.completions = self
            .stats
            .completions
            .saturating_add(u64::try_from(result.completions).unwrap_or(u64::MAX));
        result
    }

    fn emit_read_response(
        &mut self,
        output: &mut [u8],
    ) -> Result<EmitResult, PollError<Io::Error>> {
        let Some(ready) = self.dequeue_read_response() else {
            return Ok(EmitResult::default());
        };
        let segment = read_response_segment(ready.response, ready.mtu);
        let (address, payload_length) = match segment {
            Ok(segment) => segment,
            Err(error) => {
                self.synchronize_qp(ready.qp_index);
                return Err(error.into());
            }
        };
        if self
            .memory
            .read_remote(
                ready.response.rkey,
                address,
                &mut self.payload_scratch[..payload_length],
            )
            .is_err()
        {
            return Ok(self.fail_read_responder(ready.qp_index));
        }

        let opcode = segmented_opcode(
            TransferDirection::ReadResponse,
            ready.response.next_packet,
            ready.response.packet_count,
        );
        let packet = PacketSpec {
            bth: Bth::new(
                opcode,
                ready.remote_qpn,
                ready
                    .response
                    .request_psn
                    .wrapping_add(ready.response.next_packet)
                    .value(),
            ),
            reth: None,
            aeth: opcode
                .has_aeth()
                .then(|| Aeth::ack(ready.message_sequence_number.value())),
            immediate_data: None,
            payload: &self.payload_scratch[..payload_length],
        };
        if let Err(error) = transmit_packet(
            &mut self.io,
            &mut self.stats,
            self.config.maximum_packet_size,
            ready.path,
            packet,
            output,
        ) {
            self.synchronize_qp(ready.qp_index);
            return Err(error);
        }

        self.advance_read_response(ready.qp_index)?;
        Ok(EmitResult {
            transmitted: true,
            completions: 0,
        })
    }

    fn dequeue_read_response(&mut self) -> Option<ReadyReadResponse> {
        while let Some(index) = self.responder_ready.pop() {
            let ready = self
                .qps
                .get_mut(index)
                .and_then(Option::as_mut)
                .and_then(|slot| {
                    slot.responder_scheduled = false;
                    let response = slot.read_response?;
                    slot.responder_is_runnable().then_some(ReadyReadResponse {
                        qp_index: index,
                        path: slot.path,
                        remote_qpn: slot.machine.config().remote_qpn,
                        response,
                        message_sequence_number: slot.message_sequence_number,
                        mtu: slot.machine.config().path_mtu.bytes(),
                    })
                });
            if ready.is_some() {
                return ready;
            }
            self.synchronize_qp(index);
        }
        None
    }

    fn fail_read_responder(&mut self, index: usize) -> EmitResult {
        let completions = self
            .qps
            .get_mut(index)
            .and_then(Option::as_mut)
            .map_or(0, |slot| slot.enter_error(&mut self.memory));
        self.synchronize_qp(index);
        self.stats.completions = self
            .stats
            .completions
            .saturating_add(u64::try_from(completions).unwrap_or(u64::MAX));
        EmitResult {
            transmitted: false,
            completions,
        }
    }

    fn advance_read_response(&mut self, index: usize) -> Result<(), ApiError> {
        let slot = self
            .qps
            .get_mut(index)
            .and_then(Option::as_mut)
            .ok_or(ApiError::InvalidQpHandle)?;
        if let Some(active) = slot.read_response.as_mut() {
            active.next_packet += 1;
            if active.next_packet == active.packet_count {
                slot.read_response = None;
                release_lease(&mut self.memory, &mut slot.read_memory);
            }
        }
        self.synchronize_qp(index);
        Ok(())
    }

    fn emit_requester(
        &mut self,
        now: u64,
        output: &mut [u8],
    ) -> Result<EmitResult, PollError<Io::Error>> {
        let mut generated = 0;

        while let Some(index) = self.requester_ready.pop() {
            let Some(slot) = self.qps.get_mut(index).and_then(Option::as_mut) else {
                continue;
            };
            slot.requester_scheduled = false;
            start_next_request(slot, self.config.ticks_per_second);
            let Some(active) = slot.active_request else {
                self.synchronize_qp(index);
                continue;
            };
            if !matches!(active.phase, RequestPhase::Sending) {
                self.synchronize_qp(index);
                continue;
            }

            let config = slot.machine.config();
            let path = slot.path;
            let timeout_ticks = ack_timeout_ticks(config.timeout, self.config.ticks_per_second)
                .ok_or(ApiError::InvalidTicksPerSecond)?;
            let packet = match build_request_packet(
                &mut self.memory,
                &mut self.payload_scratch,
                active,
                config.path_mtu.bytes(),
                config.remote_qpn,
            ) {
                Ok(packet) => packet,
                Err(RequestPacketError::ArithmeticOverflow) => {
                    self.synchronize_qp(index);
                    self.stats.completions = self
                        .stats
                        .completions
                        .saturating_add(u64::try_from(generated).unwrap_or(u64::MAX));
                    return Err(ApiError::ArithmeticOverflow.into());
                }
                Err(RequestPacketError::LocalProtection) => {
                    generated += fail_active_and_error(
                        self.qps[index].as_mut().ok_or(ApiError::InvalidQpHandle)?,
                        &mut self.memory,
                        CompletionStatus::LocalProtectionError,
                    );
                    self.synchronize_qp(index);
                    continue;
                }
            };

            let transmitted = transmit_packet(
                &mut self.io,
                &mut self.stats,
                self.config.maximum_packet_size,
                path,
                packet,
                output,
            );
            if let Err(error) = transmitted {
                self.synchronize_qp(index);
                self.stats.completions = self
                    .stats
                    .completions
                    .saturating_add(u64::try_from(generated).unwrap_or(u64::MAX));
                return Err(error);
            }

            let slot = self.qps[index].as_mut().ok_or(ApiError::InvalidQpHandle)?;
            mark_request_packet_sent(slot, now, timeout_ticks);
            self.synchronize_qp(index);
            self.stats.completions = self
                .stats
                .completions
                .saturating_add(u64::try_from(generated).unwrap_or(u64::MAX));
            return Ok(EmitResult {
                transmitted: true,
                completions: generated,
            });
        }

        self.stats.completions = self
            .stats
            .completions
            .saturating_add(u64::try_from(generated).unwrap_or(u64::MAX));
        Ok(EmitResult {
            transmitted: false,
            completions: generated,
        })
    }

    fn prepare_requester_batch(
        &mut self,
        next_class: DataTxClass,
    ) -> Result<(Option<(PreparedWirePacket, PreparedTx)>, usize), ApiError> {
        let mut generated = 0;

        while let Some(index) = self.requester_ready.pop() {
            let Some(slot) = self.qps.get_mut(index).and_then(Option::as_mut) else {
                continue;
            };
            slot.requester_scheduled = false;
            start_next_request(slot, self.config.ticks_per_second);
            let Some(active) = slot.active_request else {
                self.synchronize_qp(index);
                continue;
            };
            if !matches!(active.phase, RequestPhase::Sending) {
                self.synchronize_qp(index);
                continue;
            }

            let config = slot.machine.config();
            let path = slot.path;
            let timeout_ticks = ack_timeout_ticks(config.timeout, self.config.ticks_per_second)
                .ok_or(ApiError::InvalidTicksPerSecond)?;
            let packet = match build_request_packet(
                &mut self.memory,
                &mut self.payload_scratch,
                active,
                config.path_mtu.bytes(),
                config.remote_qpn,
            ) {
                Ok(packet) => packet,
                Err(RequestPacketError::ArithmeticOverflow) => {
                    self.synchronize_qp(index);
                    self.stats.completions = self
                        .stats
                        .completions
                        .saturating_add(u64::try_from(generated).unwrap_or(u64::MAX));
                    return Err(ApiError::ArithmeticOverflow);
                }
                Err(RequestPacketError::LocalProtection) => {
                    generated += fail_active_and_error(
                        self.qps[index].as_mut().ok_or(ApiError::InvalidQpHandle)?,
                        &mut self.memory,
                        CompletionStatus::LocalProtectionError,
                    );
                    self.synchronize_qp(index);
                    continue;
                }
            };
            let prepared = PreparedWirePacket {
                path,
                bth: packet.bth,
                reth: packet.reth,
                aeth: packet.aeth,
                payload_length: packet.payload.len(),
            };
            self.stats.completions = self
                .stats
                .completions
                .saturating_add(u64::try_from(generated).unwrap_or(u64::MAX));
            return Ok((
                Some((
                    prepared,
                    PreparedTx::Requester {
                        qp_index: index,
                        timeout_ticks,
                        next_class,
                    },
                )),
                generated,
            ));
        }

        self.stats.completions = self
            .stats
            .completions
            .saturating_add(u64::try_from(generated).unwrap_or(u64::MAX));
        Ok((None, generated))
    }

    fn prepare_read_response_batch(
        &mut self,
        next_class: DataTxClass,
    ) -> Result<(Option<(PreparedWirePacket, PreparedTx)>, usize), ApiError> {
        let mut generated = 0;
        loop {
            let Some(ready) = self.dequeue_read_response() else {
                return Ok((None, generated));
            };
            let (address, payload_length) = match read_response_segment(ready.response, ready.mtu) {
                Ok(segment) => segment,
                Err(error) => {
                    self.synchronize_qp(ready.qp_index);
                    return Err(error);
                }
            };
            if self
                .memory
                .read_remote(
                    ready.response.rkey,
                    address,
                    &mut self.payload_scratch[..payload_length],
                )
                .is_err()
            {
                let failed = self.fail_read_responder(ready.qp_index);
                generated = generated.saturating_add(failed.completions);
                continue;
            }

            let opcode = segmented_opcode(
                TransferDirection::ReadResponse,
                ready.response.next_packet,
                ready.response.packet_count,
            );
            return Ok((
                Some((
                    PreparedWirePacket {
                        path: ready.path,
                        bth: Bth::new(
                            opcode,
                            ready.remote_qpn,
                            ready
                                .response
                                .request_psn
                                .wrapping_add(ready.response.next_packet)
                                .value(),
                        ),
                        reth: None,
                        aeth: opcode
                            .has_aeth()
                            .then(|| Aeth::ack(ready.message_sequence_number.value())),
                        payload_length,
                    },
                    PreparedTx::Responder {
                        qp_index: ready.qp_index,
                        next_class,
                    },
                )),
                generated,
            ));
        }
    }

    fn prepare_data_class_batch(
        &mut self,
        class: DataTxClass,
        next_class: DataTxClass,
    ) -> Result<(Option<(PreparedWirePacket, PreparedTx)>, usize), ApiError> {
        match class {
            DataTxClass::Requester => self.prepare_requester_batch(next_class),
            DataTxClass::Responder => self.prepare_read_response_batch(next_class),
        }
    }

    fn rollback_prepared_tx(&mut self, prepared: PreparedTx) {
        if let Some(index) = prepared.qp_index() {
            self.synchronize_qp(index);
        }
    }

    fn commit_prepared_tx(&mut self, prepared: PreparedTx, now: u64) -> Result<(), ApiError> {
        match prepared {
            PreparedTx::Control(expected) => {
                let Some(actual) = self.pending_control.pop() else {
                    return Err(ApiError::PacketIoContractViolation);
                };
                if actual != expected {
                    return Err(ApiError::PacketIoContractViolation);
                }
                self.record_control_transmit(actual);
            }
            PreparedTx::Requester {
                qp_index,
                timeout_ticks,
                next_class,
            } => {
                let slot = self
                    .qps
                    .get_mut(qp_index)
                    .and_then(Option::as_mut)
                    .ok_or(ApiError::InvalidQpHandle)?;
                mark_request_packet_sent(slot, now, timeout_ticks);
                self.next_data_tx_class = next_class;
                self.synchronize_qp(qp_index);
            }
            PreparedTx::Responder {
                qp_index,
                next_class,
            } => {
                self.next_data_tx_class = next_class;
                self.advance_read_response(qp_index)?;
            }
        }
        Ok(())
    }

    fn record_control_transmit(&mut self, reply: ControlReply) {
        match reply.aeth.class() {
            AethClass::Ack { .. } => {
                self.stats.acknowledgements = self.stats.acknowledgements.saturating_add(1);
            }
            AethClass::RnrNak { .. } => {
                self.stats.rnr_naks = self.stats.rnr_naks.saturating_add(1);
            }
            AethClass::Nak(_) | AethClass::Reserved { .. } => {
                self.stats.negative_acknowledgements =
                    self.stats.negative_acknowledgements.saturating_add(1);
            }
        }
    }

    fn synchronize_qp(&mut self, index: usize) {
        let Some(slot) = self.qps.get(index).and_then(Option::as_ref) else {
            self.deschedule_qp(index);
            return;
        };
        let requester_runnable = slot.requester_is_runnable();
        let responder_runnable = slot.responder_is_runnable();
        let timer_deadline = slot.timer_deadline();
        let generation = slot.generation;
        let timer_sequence = slot.timer_sequence;

        if requester_runnable {
            let inserted = self.requester_ready.schedule(index);
            debug_assert!(inserted || self.requester_ready.is_scheduled(index));
        } else {
            self.requester_ready.cancel(index);
        }
        if responder_runnable {
            let inserted = self.responder_ready.schedule(index);
            debug_assert!(inserted || self.responder_ready.is_scheduled(index));
        } else {
            self.responder_ready.cancel(index);
        }

        if let Ok(qp_slot) = u32::try_from(index) {
            match timer_deadline {
                Some(deadline) => {
                    let current_matches = self.timer_scheduler.get(qp_slot).is_some_and(|entry| {
                        entry.deadline() == deadline
                            && entry.qp_generation() == generation
                            && entry.sequence() == timer_sequence
                    });
                    if !current_matches {
                        let sequence = self.qps[index].as_mut().map(|slot| {
                            slot.timer_sequence = next_timer_sequence(slot.timer_sequence);
                            slot.timer_sequence
                        });
                        if let Some(sequence) = sequence {
                            let scheduled = self
                                .timer_scheduler
                                .schedule(TimerEntry::new(deadline, qp_slot, generation, sequence));
                            debug_assert!(scheduled);
                        }
                    }
                }
                None => {
                    if self.timer_scheduler.cancel(qp_slot).is_some() {
                        if let Some(slot) = self.qps[index].as_mut() {
                            slot.timer_sequence = next_timer_sequence(slot.timer_sequence);
                        }
                    }
                }
            }
        } else {
            debug_assert!(false, "QP slot index must fit QpHandle's u32 slot field");
        }

        let requester_scheduled = self.requester_ready.is_scheduled(index);
        let responder_scheduled = self.responder_ready.is_scheduled(index);
        if let Some(slot) = self.qps.get_mut(index).and_then(Option::as_mut) {
            slot.requester_scheduled = requester_scheduled;
            slot.responder_scheduled = responder_scheduled;
        }
    }

    fn deschedule_qp(&mut self, index: usize) {
        self.requester_ready.cancel(index);
        self.responder_ready.cancel(index);
        if let Ok(qp_slot) = u32::try_from(index) {
            self.timer_scheduler.cancel(qp_slot);
        }
        if let Some(slot) = self.qps.get_mut(index).and_then(Option::as_mut) {
            slot.requester_scheduled = false;
            slot.responder_scheduled = false;
            slot.timer_sequence = next_timer_sequence(slot.timer_sequence);
        }
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

    fn qp_slot(&self, handle: QpHandle) -> Result<&RcQpSlot<SQ, RQ, CQ>, ApiError> {
        let index = self.qp_index(handle)?;
        self.qps[index].as_deref().ok_or(ApiError::InvalidQpHandle)
    }

    fn qp_slot_mut(&mut self, handle: QpHandle) -> Result<&mut RcQpSlot<SQ, RQ, CQ>, ApiError> {
        let index = self.qp_index(handle)?;
        self.qps[index]
            .as_deref_mut()
            .ok_or(ApiError::InvalidQpHandle)
    }
}

impl<
    Io,
    const QPS: usize,
    const MRS: usize,
    const SQ: usize,
    const RQ: usize,
    const CQ: usize,
    const QPN_INDEX: usize,
> RcEndpoint<'_, Io, QPS, MRS, SQ, RQ, CQ, QPN_INDEX>
where
    Io: PacketBatchIo,
{
    /// Make bounded batched transport progress without packet scratch buffers.
    ///
    /// `budget` is clamped to [`MAX_BATCH_PACKETS`]. receive frames are parsed
    /// in place, and requester or responder state advances only for the prefix
    /// accepted by the packet backend.
    pub fn progress_batch(
        &mut self,
        now: u64,
        budget: usize,
    ) -> Result<RcProgress, PollError<Io::Error>> {
        let budget = budget.min(MAX_BATCH_PACKETS);
        if budget == 0 {
            return Ok(RcProgress::default());
        }

        if let Err(error) = self.io.reap_tx_completions(budget) {
            self.stats.io_errors = self.stats.io_errors.saturating_add(1);
            return Err(PollError::Io(error));
        }

        let mut progress = RcProgress::default();
        let timer_result = self.service_timers(now, budget);
        progress.completions = progress
            .completions
            .saturating_add(timer_result.completions);
        progress.retransmissions = progress
            .retransmissions
            .saturating_add(timer_result.retransmissions);

        self.receive_batch_phase(now, budget, &mut progress)?;
        self.transmit_batch_phase(now, budget, &mut progress)?;
        Ok(progress)
    }

    fn receive_batch_phase(
        &mut self,
        now: u64,
        budget: usize,
        progress: &mut RcProgress,
    ) -> Result<(), PollError<Io::Error>> {
        let receive_budget = budget.min(self.pending_control.remaining_capacity());
        if receive_budget == 0 {
            return Ok(());
        }

        let mut frames: [Option<Io::RxFrame>; MAX_BATCH_PACKETS] = core::array::from_fn(|_| None);
        let received = match self.io.receive_batch(&mut frames[..receive_budget]) {
            Ok(received) => received,
            Err(error) => {
                self.stats.io_errors = self.stats.io_errors.saturating_add(1);
                return Err(PollError::Io(error));
            }
        };
        if received > receive_budget {
            let _ = self.io.recycle_rx_batch(&mut frames[..receive_budget]);
            return Err(ApiError::PacketIoContractViolation.into());
        }
        if frames[..received].iter().any(Option::is_none) {
            let _ = self.io.recycle_rx_batch(&mut frames[..received]);
            return Err(ApiError::PacketIoContractViolation.into());
        }

        let mut processing_error = None;
        for slot in frames.iter().take(received) {
            let frame = slot.as_ref().ok_or(ApiError::PacketIoContractViolation)?;
            let packet = match self.io.rx_ipv4(frame) {
                Ok(packet) => packet,
                Err(error) => {
                    self.stats.io_errors = self.stats.io_errors.saturating_add(1);
                    processing_error = Some(PollError::Io(error));
                    break;
                }
            };
            if packet.len() > self.config.maximum_packet_size {
                self.stats.invalid_packets = self.stats.invalid_packets.saturating_add(1);
                processing_error = Some(
                    ApiError::PacketTooLarge {
                        length: packet.len(),
                        maximum: self.config.maximum_packet_size,
                    }
                    .into(),
                );
                break;
            }
            let decoded = match decode_ipv4_packet(packet) {
                Ok(decoded) => decoded,
                Err(error) => {
                    self.stats.invalid_packets = self.stats.invalid_packets.saturating_add(1);
                    processing_error = Some(PollError::Api(error));
                    break;
                }
            };
            let packet_length = packet.len();
            self.stats.receive_packets = self.stats.receive_packets.saturating_add(1);
            self.stats.receive_bytes = self
                .stats
                .receive_bytes
                .saturating_add(u64::try_from(packet_length).unwrap_or(u64::MAX));

            let state_result = process_incoming_state(
                &self.qpn_index,
                &mut self.qps,
                &mut self.memory,
                &mut self.stats,
                self.config.ticks_per_second,
                now,
                decoded,
            );
            let (index, result) = match state_result {
                Ok(result) => result,
                Err(error) => {
                    processing_error = Some(PollError::Api(error));
                    break;
                }
            };
            self.synchronize_qp(index);
            self.stats.completions = self
                .stats
                .completions
                .saturating_add(u64::try_from(result.completions).unwrap_or(u64::MAX));
            progress.received_packets = progress.received_packets.saturating_add(1);
            progress.completions = progress.completions.saturating_add(result.completions);
            progress.retransmissions = progress
                .retransmissions
                .saturating_add(result.retransmissions);
            if let Some(reply) = result.reply {
                if self.pending_control.push(reply).is_err() {
                    processing_error = Some(ApiError::PacketIoContractViolation.into());
                    break;
                }
            }
        }

        if let Err(error) = self.io.recycle_rx_batch(&mut frames[..received]) {
            self.stats.io_errors = self.stats.io_errors.saturating_add(1);
            return Err(PollError::Io(error));
        }
        if let Some(error) = processing_error {
            return Err(error);
        }
        Ok(())
    }

    fn transmit_batch_phase(
        &mut self,
        now: u64,
        budget: usize,
        progress: &mut RcProgress,
    ) -> Result<(), PollError<Io::Error>> {
        let mut batch = BatchTxBuffers::<Io::TxFrame>::default();
        let acquired = self.acquire_batch_frames(&mut batch.frames[..budget])?;
        if acquired == 0 {
            return Ok(());
        }

        let (prepared_count, preparation_error) =
            self.stage_batch_packets(acquired, &mut batch, progress);
        if prepared_count == 0 {
            self.release_batch_frames(&mut batch.frames[..acquired])?;
            return match preparation_error {
                Some(error) => Err(error),
                None => Ok(()),
            };
        }

        self.submit_staged_batch(
            now,
            acquired,
            prepared_count,
            &mut batch,
            progress,
            preparation_error,
        )
    }

    fn acquire_batch_frames(
        &mut self,
        frames: &mut [Option<Io::TxFrame>],
    ) -> Result<usize, PollError<Io::Error>> {
        let acquired = match self.io.acquire_tx_batch(frames) {
            Ok(acquired) => acquired,
            Err(error) => {
                self.stats.io_errors = self.stats.io_errors.saturating_add(1);
                return Err(PollError::Io(error));
            }
        };
        if acquired > frames.len() {
            let _ = self.io.release_tx_batch(frames);
            return Err(ApiError::PacketIoContractViolation.into());
        }
        if frames[..acquired].iter().any(Option::is_none) {
            let _ = self.io.release_tx_batch(&mut frames[..acquired]);
            return Err(ApiError::PacketIoContractViolation.into());
        }
        Ok(acquired)
    }

    fn stage_batch_packets(
        &mut self,
        acquired: usize,
        batch: &mut BatchTxBuffers<Io::TxFrame>,
        progress: &mut RcProgress,
    ) -> (usize, Option<PollError<Io::Error>>) {
        let mut prepared_count = 0;
        let mut control_offset = 0;
        let mut staging_class = self.next_data_tx_class;

        for index in 0..acquired {
            let prepared =
                match self.prepare_next_batch_tx(&mut control_offset, &mut staging_class, progress)
                {
                    Ok(prepared) => prepared,
                    Err(error) => return (prepared_count, Some(PollError::Api(error))),
                };
            let Some((wire, prepared_tx)) = prepared else {
                break;
            };

            let Some(frame) = batch.frames[index].as_ref() else {
                self.rollback_prepared_tx(prepared_tx);
                return (
                    prepared_count,
                    Some(ApiError::PacketIoContractViolation.into()),
                );
            };
            let length = match self.encode_batch_packet(frame, wire) {
                Ok(length) => length,
                Err(error) => {
                    self.rollback_prepared_tx(prepared_tx);
                    return (prepared_count, Some(error));
                }
            };
            let Some(frame) = batch.frames[index].take() else {
                self.rollback_prepared_tx(prepared_tx);
                return (
                    prepared_count,
                    Some(ApiError::PacketIoContractViolation.into()),
                );
            };
            batch.packets[index].set(frame, length);
            batch.metadata[index] = Some(prepared_tx);
            prepared_count += 1;
        }

        (prepared_count, None)
    }

    fn prepare_next_batch_tx(
        &mut self,
        control_offset: &mut usize,
        staging_class: &mut DataTxClass,
        progress: &mut RcProgress,
    ) -> Result<Option<(PreparedWirePacket, PreparedTx)>, ApiError> {
        if let Some(reply) = self.pending_control.get(*control_offset).copied() {
            *control_offset += 1;
            return Ok(Some((
                prepared_control_packet(reply),
                PreparedTx::Control(reply),
            )));
        }

        let first_class = *staging_class;
        let first_next = first_class.other();
        let (first, completions) = self.prepare_data_class_batch(first_class, first_next)?;
        progress.completions = progress.completions.saturating_add(completions);
        if first.is_some() {
            *staging_class = first_next;
            return Ok(first);
        }

        let second_class = first_class.other();
        let second_next = second_class.other();
        let (second, completions) = self.prepare_data_class_batch(second_class, second_next)?;
        progress.completions = progress.completions.saturating_add(completions);
        if second.is_some() {
            *staging_class = second_next;
        }
        Ok(second)
    }

    fn submit_staged_batch(
        &mut self,
        now: u64,
        acquired: usize,
        prepared_count: usize,
        batch: &mut BatchTxBuffers<Io::TxFrame>,
        progress: &mut RcProgress,
        preparation_error: Option<PollError<Io::Error>>,
    ) -> Result<(), PollError<Io::Error>> {
        let (accepted, submission_error) = match self
            .io
            .submit_tx_batch(&mut batch.packets[..prepared_count])
        {
            Ok(accepted) => (accepted, None),
            Err(error) => (error.submitted(), Some(error.into_error())),
        };
        if !Self::valid_batch_submission(&batch.packets, prepared_count, accepted) {
            for prepared in batch
                .metadata
                .iter()
                .take(prepared_count)
                .flatten()
                .copied()
            {
                self.rollback_prepared_tx(prepared);
            }
            for index in 0..prepared_count {
                if batch.frames[index].is_none() {
                    batch.frames[index] = batch.packets[index].take_frame();
                }
            }
            let _ = self.io.release_tx_batch(&mut batch.frames[..acquired]);
            return Err(ApiError::PacketIoContractViolation.into());
        }

        let commit_error = self.commit_accepted_batch(
            now,
            accepted,
            &batch.packets,
            &mut batch.metadata,
            progress,
        );
        for prepared in &mut batch.metadata[accepted..prepared_count] {
            if let Some(prepared) = prepared.take() {
                self.rollback_prepared_tx(prepared);
            }
        }
        for index in accepted..prepared_count {
            batch.frames[index] = batch.packets[index].take_frame();
        }
        self.release_batch_frames(&mut batch.frames[..acquired])?;

        if let Some(error) = submission_error {
            self.stats.io_errors = self.stats.io_errors.saturating_add(1);
            return Err(PollError::Io(error));
        }
        if let Some(error) = commit_error {
            return Err(PollError::Api(error));
        }
        if let Some(error) = preparation_error {
            return Err(error);
        }
        Ok(())
    }

    fn valid_batch_submission(
        packets: &[TxPacket<Io::TxFrame>; MAX_BATCH_PACKETS],
        prepared_count: usize,
        accepted: usize,
    ) -> bool {
        accepted <= prepared_count
            && packets[..accepted]
                .iter()
                .all(|packet| packet.frame().is_none())
            && packets[accepted..prepared_count]
                .iter()
                .all(|packet| packet.frame().is_some())
    }

    fn commit_accepted_batch(
        &mut self,
        now: u64,
        accepted: usize,
        packets: &[TxPacket<Io::TxFrame>; MAX_BATCH_PACKETS],
        metadata: &mut [Option<PreparedTx>; MAX_BATCH_PACKETS],
        progress: &mut RcProgress,
    ) -> Option<ApiError> {
        let mut first_error = None;
        for index in 0..accepted {
            let Some(prepared) = metadata[index].take() else {
                first_error.get_or_insert(ApiError::PacketIoContractViolation);
                continue;
            };
            if let Err(error) = self.commit_prepared_tx(prepared, now) {
                first_error.get_or_insert(error);
            }
            self.stats.transmit_packets = self.stats.transmit_packets.saturating_add(1);
            self.stats.transmit_bytes = self
                .stats
                .transmit_bytes
                .saturating_add(u64::try_from(packets[index].len()).unwrap_or(u64::MAX));
            progress.transmitted_packets = progress.transmitted_packets.saturating_add(1);
        }
        first_error
    }

    fn release_batch_frames(
        &mut self,
        frames: &mut [Option<Io::TxFrame>],
    ) -> Result<(), PollError<Io::Error>> {
        if let Err(error) = self.io.release_tx_batch(frames) {
            self.stats.io_errors = self.stats.io_errors.saturating_add(1);
            return Err(PollError::Io(error));
        }
        Ok(())
    }

    fn encode_batch_packet(
        &mut self,
        frame: &Io::TxFrame,
        prepared: PreparedWirePacket,
    ) -> Result<usize, PollError<Io::Error>> {
        let maximum_packet_size = self.config.maximum_packet_size;
        let payload = &self.payload_scratch[..prepared.payload_length];
        let output = match self.io.tx_ipv4_buffer(frame) {
            Ok(output) => output,
            Err(error) => {
                self.stats.io_errors = self.stats.io_errors.saturating_add(1);
                return Err(PollError::Io(error));
            }
        };
        let length = encode_ipv4_packet(
            prepared.path,
            PacketSpec {
                bth: prepared.bth,
                reth: prepared.reth,
                aeth: prepared.aeth,
                immediate_data: None,
                payload,
            },
            output,
        )?;
        if length > maximum_packet_size {
            return Err(ApiError::PacketTooLarge {
                length,
                maximum: maximum_packet_size,
            }
            .into());
        }
        Ok(length)
    }
}

fn prepared_control_packet(reply: ControlReply) -> PreparedWirePacket {
    PreparedWirePacket {
        path: reply.path,
        bth: Bth::new(
            Opcode::Acknowledge,
            reply.destination_qpn,
            reply.psn.value(),
        ),
        reth: None,
        aeth: Some(reply.aeth),
        payload_length: 0,
    }
}

fn process_incoming_state<
    const QPS: usize,
    const MRS: usize,
    const SQ: usize,
    const RQ: usize,
    const CQ: usize,
    const QPN_INDEX: usize,
>(
    qpn_index: &QpnTable<QPN_INDEX>,
    qps: &mut [Option<Box<RcQpSlot<SQ, RQ, CQ>>>; QPS],
    memory: &mut MemoryRegistry<'_, MRS>,
    stats: &mut RcEndpointStats,
    ticks_per_second: u64,
    now: u64,
    decoded: DecodedPacket<'_>,
) -> Result<(usize, HandlerResult), ApiError> {
    let destination_qpn = decoded.transport.bth.destination_qpn;
    let Some(index) = qpn_slot(qpn_index, destination_qpn) else {
        stats.unknown_qp_packets = stats.unknown_qp_packets.saturating_add(1);
        return Err(ApiError::UnknownDestinationQpn(destination_qpn));
    };

    let slot = qps
        .get_mut(index)
        .and_then(Option::as_mut)
        .ok_or(ApiError::InvalidQpHandle)?;
    if decoded.ipv4.source != slot.path.destination || decoded.ipv4.destination != slot.path.source
    {
        stats.peer_mismatch_packets = stats.peer_mismatch_packets.saturating_add(1);
        return Err(ApiError::PeerAddressMismatch {
            source: decoded.ipv4.source,
            destination: decoded.ipv4.destination,
        });
    }
    if !slot.machine.can_receive() {
        return Err(ApiError::QpNotReady(slot.machine.state()));
    }

    let result = if decoded.transport.bth.opcode.is_request() {
        handle_request_packet(slot, memory, decoded.transport, stats)
    } else {
        handle_response_packet(
            slot,
            memory,
            decoded.transport,
            now,
            ticks_per_second,
            stats,
        )
    };
    Ok((index, result))
}

#[derive(Clone, Copy, Debug, Default)]
struct EmitResult {
    transmitted: bool,
    completions: usize,
}

#[derive(Clone, Copy, Debug)]
enum TransferDirection {
    Send,
    Write,
    ReadResponse,
}

fn maximum_packet_for_mtu(mtu: usize) -> Result<usize, ApiError> {
    IPV4_HEADER_LEN
        .checked_add(UDP_HEADER_LEN)
        .and_then(|value| value.checked_add(BTH_LEN))
        .and_then(|value| value.checked_add(RETH_LEN.max(AETH_LEN)))
        .and_then(|value| value.checked_add(mtu))
        .and_then(|value| value.checked_add(3))
        .and_then(|value| value.checked_add(ICRC_LEN))
        .ok_or(ApiError::ArithmeticOverflow)
}

fn validate_posted_work<const MRS: usize>(
    memory: &MemoryRegistry<'_, MRS>,
    work: WorkRequest,
    mtu: usize,
) -> Result<(), ApiError> {
    let packets = packet_count(work.sge.length, mtu);
    if packets > MAX_OUTSTANDING_PACKETS {
        return Err(ApiError::WorkRequestTooLarge {
            packets,
            maximum: MAX_OUTSTANDING_PACKETS,
        });
    }
    let length = usize::try_from(work.sge.length).map_err(|_| ApiError::ArithmeticOverflow)?;
    match work.kind {
        WorkRequestKind::Send => {
            memory.validate_local_read(work.sge.lkey, work.sge.address, length)?;
        }
        WorkRequestKind::RdmaWrite { remote_address, .. } => {
            memory.validate_local_read(work.sge.lkey, work.sge.address, length)?;
            remote_address
                .checked_add(u64::from(work.sge.length))
                .ok_or(ApiError::ArithmeticOverflow)?;
        }
        WorkRequestKind::RdmaRead { remote_address, .. } => {
            memory.validate_local_write(work.sge.lkey, work.sge.address, length)?;
            remote_address
                .checked_add(u64::from(work.sge.length))
                .ok_or(ApiError::ArithmeticOverflow)?;
        }
    }
    Ok(())
}

fn packet_count(length: u32, mtu: usize) -> u32 {
    if length == 0 {
        return 1;
    }
    let length = u64::from(length);
    let mtu = u64::try_from(mtu).unwrap_or(u64::MAX);
    u32::try_from(length.div_ceil(mtu)).unwrap_or(u32::MAX)
}

const fn next_timer_sequence(sequence: u32) -> u32 {
    let next = sequence.wrapping_add(1);
    if next == 0 { 1 } else { next }
}

fn segment_bounds(length: u32, mtu: usize, index: u32) -> Option<(usize, usize)> {
    let total = usize::try_from(length).ok()?;
    if total == 0 {
        return (index == 0).then_some((0, 0));
    }
    let index = usize::try_from(index).ok()?;
    let offset = index.checked_mul(mtu)?;
    if offset >= total {
        return None;
    }
    Some((offset, total.saturating_sub(offset).min(mtu)))
}

fn read_response_segment(
    response: ReadResponseState,
    mtu: usize,
) -> Result<(u64, usize), ApiError> {
    let (offset, payload_length) = segment_bounds(response.length, mtu, response.next_packet)
        .ok_or(ApiError::ArithmeticOverflow)?;
    let offset = u64::try_from(offset).map_err(|_| ApiError::ArithmeticOverflow)?;
    let address = response
        .address
        .checked_add(offset)
        .ok_or(ApiError::ArithmeticOverflow)?;
    Ok((address, payload_length))
}

fn segmented_opcode(direction: TransferDirection, index: u32, count: u32) -> Opcode {
    let first = index == 0;
    let last = index + 1 == count;
    match (direction, first, last) {
        (TransferDirection::Send, true, true) => Opcode::SendOnly,
        (TransferDirection::Send, true, false) => Opcode::SendFirst,
        (TransferDirection::Send, false, true) => Opcode::SendLast,
        (TransferDirection::Send, false, false) => Opcode::SendMiddle,
        (TransferDirection::Write, true, true) => Opcode::RdmaWriteOnly,
        (TransferDirection::Write, true, false) => Opcode::RdmaWriteFirst,
        (TransferDirection::Write, false, true) => Opcode::RdmaWriteLast,
        (TransferDirection::Write, false, false) => Opcode::RdmaWriteMiddle,
        (TransferDirection::ReadResponse, true, true) => Opcode::RdmaReadResponseOnly,
        (TransferDirection::ReadResponse, true, false) => Opcode::RdmaReadResponseFirst,
        (TransferDirection::ReadResponse, false, true) => Opcode::RdmaReadResponseLast,
        (TransferDirection::ReadResponse, false, false) => Opcode::RdmaReadResponseMiddle,
    }
}

fn start_next_request<const SQ: usize, const RQ: usize, const CQ: usize>(
    slot: &mut RcQpSlot<SQ, RQ, CQ>,
    ticks_per_second: u64,
) {
    if slot.active_request.is_some() || !slot.machine.can_send() {
        return;
    }
    let Some(work) = slot.send_queue.front().map(|posted| posted.work) else {
        return;
    };
    let config = slot.machine.config();
    let count = packet_count(work.sge.length, config.path_mtu.bytes());
    let Some(first_psn) = slot.send_window.reserve_many(count) else {
        return;
    };
    let timeout_ticks = ack_timeout_ticks(config.timeout, ticks_per_second).unwrap_or(u64::MAX);
    let policy = RetryPolicy::new(config.retry_count, config.rnr_retry_count, timeout_ticks)
        .expect("validated QP retry counts");
    let Some(posted) = slot.send_queue.pop() else {
        return;
    };
    debug_assert_eq!(posted.work, work);
    slot.active_memory = posted.lease;
    slot.active_request = Some(ActiveRequest {
        work,
        first_psn,
        last_psn: first_psn.wrapping_add(count - 1),
        packet_count: count,
        next_packet: 0,
        transmitted_packets: 0,
        read_packets_received: 0,
        bytes_received: 0,
        retry_budget: RetryBudget::new(policy),
        timer: Timer::new(),
        phase: RequestPhase::Sending,
    });
}

fn read_local_segment<const MRS: usize>(
    memory: &mut MemoryRegistry<'_, MRS>,
    work: WorkRequest,
    offset: usize,
    output: &mut [u8],
) -> Result<(), MemoryError> {
    let address = work
        .sge
        .address
        .checked_add(u64::try_from(offset).map_err(|_| MemoryError::AddressOverflow)?)
        .ok_or(MemoryError::AddressOverflow)?;
    memory.read_local(work.sge.lkey, address, output)
}

fn transmit_packet<Io: PacketIo>(
    io: &mut Io,
    stats: &mut RcEndpointStats,
    maximum_packet_size: usize,
    path: Ipv4Path,
    packet: PacketSpec<'_>,
    output: &mut [u8],
) -> Result<usize, PollError<Io::Error>> {
    let length = encode_ipv4_packet(path, packet, output)?;
    if length > maximum_packet_size {
        return Err(ApiError::PacketTooLarge {
            length,
            maximum: maximum_packet_size,
        }
        .into());
    }
    if let Err(error) = io.transmit_ipv4(&output[..length]) {
        stats.io_errors = stats.io_errors.saturating_add(1);
        return Err(PollError::Io(error));
    }
    stats.transmit_packets = stats.transmit_packets.saturating_add(1);
    stats.transmit_bytes = stats
        .transmit_bytes
        .saturating_add(u64::try_from(length).unwrap_or(u64::MAX));
    Ok(length)
}

fn control_reply<const SQ: usize, const RQ: usize, const CQ: usize>(
    slot: &RcQpSlot<SQ, RQ, CQ>,
    psn: Psn,
    aeth: Aeth,
) -> ControlReply {
    ControlReply {
        path: slot.path,
        destination_qpn: slot.machine.config().remote_qpn,
        psn,
        aeth,
    }
}

fn ack_reply<const SQ: usize, const RQ: usize, const CQ: usize>(
    slot: &RcQpSlot<SQ, RQ, CQ>,
    psn: Psn,
) -> ControlReply {
    control_reply(slot, psn, Aeth::ack(slot.message_sequence_number.value()))
}

fn nak_reply<const SQ: usize, const RQ: usize, const CQ: usize>(
    slot: &RcQpSlot<SQ, RQ, CQ>,
    psn: Psn,
    syndrome: u8,
) -> ControlReply {
    control_reply(
        slot,
        psn,
        Aeth {
            syndrome,
            message_sequence_number: slot.message_sequence_number.value(),
        },
    )
}

fn build_request_packet<'packet, const MRS: usize>(
    memory: &mut MemoryRegistry<'_, MRS>,
    payload_scratch: &'packet mut [u8],
    active: ActiveRequest,
    mtu: usize,
    remote_qpn: u32,
) -> Result<PacketSpec<'packet>, RequestPacketError> {
    let (direction, remote) = match active.work.kind {
        WorkRequestKind::Send => (TransferDirection::Send, None),
        WorkRequestKind::RdmaWrite {
            remote_address,
            rkey,
        } => (TransferDirection::Write, Some((remote_address, rkey))),
        WorkRequestKind::RdmaRead {
            remote_address,
            rkey,
        } => {
            let mut bth = Bth::new(
                Opcode::RdmaReadRequest,
                remote_qpn,
                active.first_psn.value(),
            );
            bth.ack_request = true;
            return Ok(PacketSpec {
                bth,
                reth: Some(Reth {
                    virtual_address: remote_address,
                    remote_key: rkey,
                    dma_length: active.work.sge.length,
                }),
                aeth: None,
                immediate_data: None,
                payload: &[],
            });
        }
    };

    let (offset, length) = segment_bounds(active.work.sge.length, mtu, active.next_packet)
        .ok_or(RequestPacketError::ArithmeticOverflow)?;
    read_local_segment(memory, active.work, offset, &mut payload_scratch[..length])
        .map_err(|_error| RequestPacketError::LocalProtection)?;

    let opcode = segmented_opcode(direction, active.next_packet, active.packet_count);
    let mut bth = Bth::new(
        opcode,
        remote_qpn,
        active.first_psn.wrapping_add(active.next_packet).value(),
    );
    bth.ack_request = active.next_packet + 1 == active.packet_count;
    let reth = remote.and_then(|(remote_address, rkey)| {
        (active.next_packet == 0).then_some(Reth {
            virtual_address: remote_address,
            remote_key: rkey,
            dma_length: active.work.sge.length,
        })
    });
    Ok(PacketSpec {
        bth,
        reth,
        aeth: None,
        immediate_data: None,
        payload: &payload_scratch[..length],
    })
}

fn mark_request_packet_sent<const SQ: usize, const RQ: usize, const CQ: usize>(
    slot: &mut RcQpSlot<SQ, RQ, CQ>,
    now: u64,
    timeout_ticks: u64,
) {
    let Some(current) = slot.active_request.as_mut() else {
        return;
    };
    match current.work.kind {
        WorkRequestKind::RdmaRead { .. } => {
            current.transmitted_packets = current.transmitted_packets.max(1);
            current.phase = RequestPhase::Waiting;
            current.timer.arm(now, timeout_ticks);
        }
        WorkRequestKind::Send | WorkRequestKind::RdmaWrite { .. } => {
            current.next_packet += 1;
            current.transmitted_packets = current.transmitted_packets.max(current.next_packet);
            if current.next_packet == current.packet_count {
                current.phase = RequestPhase::Waiting;
                current.timer.arm(now, timeout_ticks);
            }
        }
    }
}

fn handle_request_packet<const MRS: usize, const SQ: usize, const RQ: usize, const CQ: usize>(
    slot: &mut RcQpSlot<SQ, RQ, CQ>,
    memory: &mut MemoryRegistry<'_, MRS>,
    packet: PacketRef<'_>,
    stats: &mut RcEndpointStats,
) -> HandlerResult {
    let received_psn = Psn::new_truncated(packet.bth.psn);
    match slot.receive_psn.classify(received_psn) {
        ReceiveDisposition::Future => {
            stats.sequence_errors = stats.sequence_errors.saturating_add(1);
            return HandlerResult {
                reply: Some(control_reply(
                    slot,
                    slot.receive_psn.expected(),
                    Aeth::psn_nak(slot.message_sequence_number.value()),
                )),
                ..HandlerResult::default()
            };
        }
        ReceiveDisposition::Duplicate => {
            stats.duplicate_requests = stats.duplicate_requests.saturating_add(1);
            if matches!(packet.bth.opcode, Opcode::RdmaReadRequest) {
                return replay_read_request(slot, memory, packet, received_psn);
            }
            return HandlerResult {
                reply: Some(ack_reply(slot, received_psn)),
                ..HandlerResult::default()
            };
        }
        ReceiveDisposition::Expected => {}
    }

    if packet.bth.partition_key != Bth::DEFAULT_PKEY {
        return fatal_request_error(slot, memory, received_psn, Aeth::NAK_INVALID_REQUEST);
    }

    match packet.bth.opcode {
        Opcode::SendOnly | Opcode::SendFirst | Opcode::SendMiddle | Opcode::SendLast => {
            handle_send_request(slot, memory, packet, received_psn)
        }
        Opcode::RdmaWriteOnly
        | Opcode::RdmaWriteFirst
        | Opcode::RdmaWriteMiddle
        | Opcode::RdmaWriteLast => handle_write_request(slot, memory, packet, received_psn),
        Opcode::RdmaReadRequest => handle_read_request(slot, memory, packet, received_psn),
        Opcode::SendLastWithImmediate
        | Opcode::SendOnlyWithImmediate
        | Opcode::RdmaWriteLastWithImmediate
        | Opcode::RdmaWriteOnlyWithImmediate
        | Opcode::RdmaReadResponseFirst
        | Opcode::RdmaReadResponseMiddle
        | Opcode::RdmaReadResponseLast
        | Opcode::RdmaReadResponseOnly
        | Opcode::Acknowledge => {
            fatal_request_error(slot, memory, received_psn, Aeth::NAK_INVALID_REQUEST)
        }
    }
}

fn replay_read_request<const MRS: usize, const SQ: usize, const RQ: usize, const CQ: usize>(
    slot: &mut RcQpSlot<SQ, RQ, CQ>,
    memory: &mut MemoryRegistry<'_, MRS>,
    packet: PacketRef<'_>,
    psn: Psn,
) -> HandlerResult {
    let Some(reth) = packet.reth else {
        return fatal_request_error(slot, memory, psn, Aeth::NAK_INVALID_REQUEST);
    };
    let replay = ReadResponseState {
        request_psn: psn,
        address: reth.virtual_address,
        rkey: reth.remote_key,
        length: reth.dma_length,
        packet_count: packet_count(reth.dma_length, slot.machine.config().path_mtu.bytes()),
        next_packet: 0,
    };
    if memory
        .validate_remote_read(
            reth.remote_key,
            reth.virtual_address,
            usize::try_from(reth.dma_length).unwrap_or(usize::MAX),
        )
        .is_err()
    {
        return fatal_request_error(slot, memory, psn, Aeth::NAK_REMOTE_ACCESS_ERROR);
    }

    if slot.read_replay != Some(replay)
        || slot
            .read_response
            .is_some_and(|active| active.request_psn != psn)
    {
        return HandlerResult {
            reply: Some(control_reply(
                slot,
                psn,
                Aeth::rnr_nak(slot.message_sequence_number.value(), slot.rnr_nak_timer),
            )),
            ..HandlerResult::default()
        };
    }

    if slot.read_memory.is_none() {
        match memory.retain_remote(replay.rkey) {
            Ok(lease) => slot.read_memory = Some(lease),
            Err(_) => return fatal_request_error(slot, memory, psn, Aeth::NAK_REMOTE_ACCESS_ERROR),
        }
    }
    slot.read_response = Some(replay);
    HandlerResult::default()
}

fn handle_send_request<const MRS: usize, const SQ: usize, const RQ: usize, const CQ: usize>(
    slot: &mut RcQpSlot<SQ, RQ, CQ>,
    memory: &mut MemoryRegistry<'_, MRS>,
    packet: PacketRef<'_>,
    psn: Psn,
) -> HandlerResult {
    let position = packet.bth.opcode.position();
    let mtu = slot.machine.config().path_mtu.bytes();
    if !valid_request_payload_length(position, packet.payload.len(), mtu) {
        return fatal_request_error(slot, memory, psn, Aeth::NAK_INVALID_REQUEST);
    }

    match position {
        SegmentPosition::Only | SegmentPosition::First => {
            handle_send_start(slot, memory, packet, psn, position)
        }
        SegmentPosition::Middle | SegmentPosition::Last => {
            handle_send_continuation(slot, memory, packet, psn, position)
        }
    }
}

fn handle_send_start<const MRS: usize, const SQ: usize, const RQ: usize, const CQ: usize>(
    slot: &mut RcQpSlot<SQ, RQ, CQ>,
    memory: &mut MemoryRegistry<'_, MRS>,
    packet: PacketRef<'_>,
    psn: Psn,
    position: SegmentPosition,
) -> HandlerResult {
    if slot.inbound_message.is_some() {
        return fatal_request_error(slot, memory, psn, Aeth::NAK_INVALID_REQUEST);
    }
    let Some(posted) = slot.receive_queue.pop() else {
        return HandlerResult {
            reply: Some(control_reply(
                slot,
                psn,
                Aeth::rnr_nak(slot.message_sequence_number.value(), slot.rnr_nak_timer),
            )),
            ..HandlerResult::default()
        };
    };
    let work = posted.work;
    slot.inbound_memory = posted.lease;
    if packet.payload.len() > usize::try_from(work.sge.length).unwrap_or(usize::MAX) {
        let mut result = fatal_request_error(slot, memory, psn, Aeth::NAK_INVALID_REQUEST);
        result.completions +=
            slot.finish_receive(memory, work, CompletionStatus::LocalLengthError, 0);
        return result;
    }
    if memory
        .write_local(work.sge.lkey, work.sge.address, packet.payload)
        .is_err()
    {
        let mut result = fatal_request_error(slot, memory, psn, Aeth::NAK_REMOTE_OPERATION_ERROR);
        result.completions +=
            slot.finish_receive(memory, work, CompletionStatus::LocalProtectionError, 0);
        return result;
    }

    let bytes_written = u32::try_from(packet.payload.len()).unwrap_or(u32::MAX);
    slot.receive_psn.observe(psn);
    if matches!(position, SegmentPosition::Only) {
        slot.message_sequence_number = slot.message_sequence_number.next();
        let completions =
            slot.finish_receive(memory, work, CompletionStatus::Success, bytes_written);
        HandlerResult {
            reply: Some(ack_reply(slot, psn)),
            completions,
            retransmissions: 0,
        }
    } else {
        slot.inbound_message = Some(InboundMessage::Send {
            work,
            bytes_written,
        });
        HandlerResult {
            reply: Some(ack_reply(slot, psn)),
            ..HandlerResult::default()
        }
    }
}

fn handle_send_continuation<const MRS: usize, const SQ: usize, const RQ: usize, const CQ: usize>(
    slot: &mut RcQpSlot<SQ, RQ, CQ>,
    memory: &mut MemoryRegistry<'_, MRS>,
    packet: PacketRef<'_>,
    psn: Psn,
    position: SegmentPosition,
) -> HandlerResult {
    let Some(InboundMessage::Send {
        work,
        bytes_written,
    }) = slot.inbound_message
    else {
        return fatal_request_error(slot, memory, psn, Aeth::NAK_INVALID_REQUEST);
    };
    let Some(new_total) =
        bytes_written.checked_add(u32::try_from(packet.payload.len()).unwrap_or(u32::MAX))
    else {
        return fail_receive_message(slot, memory, psn, CompletionStatus::LocalLengthError);
    };
    if new_total > work.sge.length {
        return fail_receive_message(slot, memory, psn, CompletionStatus::LocalLengthError);
    }
    let Some(address) = work.sge.address.checked_add(u64::from(bytes_written)) else {
        return fail_receive_message(slot, memory, psn, CompletionStatus::LocalLengthError);
    };
    if memory
        .write_local(work.sge.lkey, address, packet.payload)
        .is_err()
    {
        return fail_receive_message(slot, memory, psn, CompletionStatus::LocalProtectionError);
    }

    slot.receive_psn.observe(psn);
    if matches!(position, SegmentPosition::Last) {
        slot.inbound_message = None;
        slot.message_sequence_number = slot.message_sequence_number.next();
        let completions = slot.finish_receive(memory, work, CompletionStatus::Success, new_total);
        HandlerResult {
            reply: Some(ack_reply(slot, psn)),
            completions,
            retransmissions: 0,
        }
    } else {
        slot.inbound_message = Some(InboundMessage::Send {
            work,
            bytes_written: new_total,
        });
        HandlerResult {
            reply: Some(ack_reply(slot, psn)),
            ..HandlerResult::default()
        }
    }
}

fn handle_write_request<const MRS: usize, const SQ: usize, const RQ: usize, const CQ: usize>(
    slot: &mut RcQpSlot<SQ, RQ, CQ>,
    memory: &mut MemoryRegistry<'_, MRS>,
    packet: PacketRef<'_>,
    psn: Psn,
) -> HandlerResult {
    let position = packet.bth.opcode.position();
    let mtu = slot.machine.config().path_mtu.bytes();
    if !valid_request_payload_length(position, packet.payload.len(), mtu) {
        return fatal_request_error(slot, memory, psn, Aeth::NAK_INVALID_REQUEST);
    }

    match position {
        SegmentPosition::Only | SegmentPosition::First => {
            handle_write_start(slot, memory, packet, psn, position)
        }
        SegmentPosition::Middle | SegmentPosition::Last => {
            handle_write_continuation(slot, memory, packet, psn, position)
        }
    }
}

fn handle_write_start<const MRS: usize, const SQ: usize, const RQ: usize, const CQ: usize>(
    slot: &mut RcQpSlot<SQ, RQ, CQ>,
    memory: &mut MemoryRegistry<'_, MRS>,
    packet: PacketRef<'_>,
    psn: Psn,
    position: SegmentPosition,
) -> HandlerResult {
    if slot.inbound_message.is_some() {
        return fatal_request_error(slot, memory, psn, Aeth::NAK_INVALID_REQUEST);
    }
    let Some(reth) = packet.reth else {
        return fatal_request_error(slot, memory, psn, Aeth::NAK_INVALID_REQUEST);
    };
    let payload_length = u32::try_from(packet.payload.len()).unwrap_or(u32::MAX);
    let length_is_valid = match position {
        SegmentPosition::Only => payload_length == reth.dma_length,
        SegmentPosition::First => payload_length < reth.dma_length,
        SegmentPosition::Middle | SegmentPosition::Last => false,
    };
    if !length_is_valid {
        return fatal_request_error(slot, memory, psn, Aeth::NAK_INVALID_REQUEST);
    }
    if memory
        .validate_remote_write(
            reth.remote_key,
            reth.virtual_address,
            usize::try_from(reth.dma_length).unwrap_or(usize::MAX),
        )
        .is_err()
    {
        return fatal_request_error(slot, memory, psn, Aeth::NAK_REMOTE_ACCESS_ERROR);
    }

    if matches!(position, SegmentPosition::First) {
        match memory.retain_remote(reth.remote_key) {
            Ok(lease) => slot.inbound_memory = Some(lease),
            Err(_) => return fatal_request_error(slot, memory, psn, Aeth::NAK_REMOTE_ACCESS_ERROR),
        }
    }
    if memory
        .write_remote(reth.remote_key, reth.virtual_address, packet.payload)
        .is_err()
    {
        return fatal_request_error(slot, memory, psn, Aeth::NAK_REMOTE_ACCESS_ERROR);
    }

    slot.receive_psn.observe(psn);
    if matches!(position, SegmentPosition::Only) {
        slot.message_sequence_number = slot.message_sequence_number.next();
    } else {
        slot.inbound_message = Some(InboundMessage::Write {
            address: reth.virtual_address,
            rkey: reth.remote_key,
            total_length: reth.dma_length,
            bytes_written: payload_length,
        });
    }
    HandlerResult {
        reply: Some(ack_reply(slot, psn)),
        ..HandlerResult::default()
    }
}

fn handle_write_continuation<
    const MRS: usize,
    const SQ: usize,
    const RQ: usize,
    const CQ: usize,
>(
    slot: &mut RcQpSlot<SQ, RQ, CQ>,
    memory: &mut MemoryRegistry<'_, MRS>,
    packet: PacketRef<'_>,
    psn: Psn,
    position: SegmentPosition,
) -> HandlerResult {
    let Some(InboundMessage::Write {
        address,
        rkey,
        total_length,
        bytes_written,
    }) = slot.inbound_message
    else {
        return fatal_request_error(slot, memory, psn, Aeth::NAK_INVALID_REQUEST);
    };
    let Some(new_total) =
        bytes_written.checked_add(u32::try_from(packet.payload.len()).unwrap_or(u32::MAX))
    else {
        return fatal_request_error(slot, memory, psn, Aeth::NAK_INVALID_REQUEST);
    };
    let valid_position = match position {
        SegmentPosition::Middle => new_total < total_length,
        SegmentPosition::Last => new_total == total_length,
        SegmentPosition::First | SegmentPosition::Only => false,
    };
    if !valid_position {
        return fatal_request_error(slot, memory, psn, Aeth::NAK_INVALID_REQUEST);
    }
    let Some(segment_address) = address.checked_add(u64::from(bytes_written)) else {
        return fatal_request_error(slot, memory, psn, Aeth::NAK_REMOTE_ACCESS_ERROR);
    };
    if memory
        .write_remote(rkey, segment_address, packet.payload)
        .is_err()
    {
        return fatal_request_error(slot, memory, psn, Aeth::NAK_REMOTE_ACCESS_ERROR);
    }

    slot.receive_psn.observe(psn);
    if matches!(position, SegmentPosition::Last) {
        slot.inbound_message = None;
        release_lease(memory, &mut slot.inbound_memory);
        slot.message_sequence_number = slot.message_sequence_number.next();
    } else {
        slot.inbound_message = Some(InboundMessage::Write {
            address,
            rkey,
            total_length,
            bytes_written: new_total,
        });
    }
    HandlerResult {
        reply: Some(ack_reply(slot, psn)),
        ..HandlerResult::default()
    }
}

fn handle_read_request<const MRS: usize, const SQ: usize, const RQ: usize, const CQ: usize>(
    slot: &mut RcQpSlot<SQ, RQ, CQ>,
    memory: &mut MemoryRegistry<'_, MRS>,
    packet: PacketRef<'_>,
    psn: Psn,
) -> HandlerResult {
    if slot.inbound_message.is_some() {
        return fatal_request_error(slot, memory, psn, Aeth::NAK_INVALID_REQUEST);
    }
    if slot.read_response.is_some() {
        return HandlerResult {
            reply: Some(control_reply(
                slot,
                psn,
                Aeth::rnr_nak(slot.message_sequence_number.value(), slot.rnr_nak_timer),
            )),
            ..HandlerResult::default()
        };
    }
    let Some(reth) = packet.reth else {
        return fatal_request_error(slot, memory, psn, Aeth::NAK_INVALID_REQUEST);
    };
    if memory
        .validate_remote_read(
            reth.remote_key,
            reth.virtual_address,
            usize::try_from(reth.dma_length).unwrap_or(usize::MAX),
        )
        .is_err()
    {
        return fatal_request_error(slot, memory, psn, Aeth::NAK_REMOTE_ACCESS_ERROR);
    }

    match memory.retain_remote(reth.remote_key) {
        Ok(lease) => slot.read_memory = Some(lease),
        Err(_) => return fatal_request_error(slot, memory, psn, Aeth::NAK_REMOTE_ACCESS_ERROR),
    }
    let packets = packet_count(reth.dma_length, slot.machine.config().path_mtu.bytes());
    slot.receive_psn.observe_span(psn, packets);
    slot.message_sequence_number = slot.message_sequence_number.next();
    let response = ReadResponseState {
        request_psn: psn,
        address: reth.virtual_address,
        rkey: reth.remote_key,
        length: reth.dma_length,
        packet_count: packets,
        next_packet: 0,
    };
    slot.read_replay = Some(response);
    slot.read_response = Some(response);
    HandlerResult::default()
}

fn valid_request_payload_length(position: SegmentPosition, length: usize, mtu: usize) -> bool {
    match position {
        SegmentPosition::First | SegmentPosition::Middle => length == mtu,
        SegmentPosition::Last | SegmentPosition::Only => length <= mtu,
    }
}

fn fail_receive_message<const MRS: usize, const SQ: usize, const RQ: usize, const CQ: usize>(
    slot: &mut RcQpSlot<SQ, RQ, CQ>,
    memory: &mut MemoryRegistry<'_, MRS>,
    psn: Psn,
    status: CompletionStatus,
) -> HandlerResult {
    let work = match slot.inbound_message.take() {
        Some(InboundMessage::Send { work, .. }) => Some(work),
        Some(InboundMessage::Write { .. }) | None => None,
    };
    let reply = nak_reply(slot, psn, Aeth::NAK_INVALID_REQUEST);
    let mut completions = work.map_or(0, |work| slot.finish_receive(memory, work, status, 0));
    completions += slot.enter_error(memory);
    HandlerResult {
        reply: Some(reply),
        completions,
        retransmissions: 0,
    }
}

fn fatal_request_error<const MRS: usize, const SQ: usize, const RQ: usize, const CQ: usize>(
    slot: &mut RcQpSlot<SQ, RQ, CQ>,
    memory: &mut MemoryRegistry<'_, MRS>,
    psn: Psn,
    syndrome: u8,
) -> HandlerResult {
    let reply = nak_reply(slot, psn, syndrome);
    let completions = slot.enter_error(memory);
    HandlerResult {
        reply: Some(reply),
        completions,
        retransmissions: 0,
    }
}

fn handle_response_packet<const MRS: usize, const SQ: usize, const RQ: usize, const CQ: usize>(
    slot: &mut RcQpSlot<SQ, RQ, CQ>,
    memory: &mut MemoryRegistry<'_, MRS>,
    packet: PacketRef<'_>,
    now: u64,
    ticks_per_second: u64,
    stats: &mut RcEndpointStats,
) -> HandlerResult {
    if slot.active_request.is_none() {
        return HandlerResult::default();
    }

    match packet.bth.opcode {
        Opcode::Acknowledge => {
            let Some(aeth) = packet.aeth else {
                return fail_active_transport(slot, memory);
            };
            handle_aeth_response(
                slot,
                memory,
                aeth,
                Psn::new_truncated(packet.bth.psn),
                now,
                ticks_per_second,
                stats,
            )
        }
        Opcode::RdmaReadResponseFirst
        | Opcode::RdmaReadResponseMiddle
        | Opcode::RdmaReadResponseLast
        | Opcode::RdmaReadResponseOnly => {
            handle_read_response(slot, memory, packet, now, ticks_per_second, stats)
        }
        Opcode::SendFirst
        | Opcode::SendMiddle
        | Opcode::SendLast
        | Opcode::SendLastWithImmediate
        | Opcode::SendOnly
        | Opcode::SendOnlyWithImmediate
        | Opcode::RdmaWriteFirst
        | Opcode::RdmaWriteMiddle
        | Opcode::RdmaWriteLast
        | Opcode::RdmaWriteLastWithImmediate
        | Opcode::RdmaWriteOnly
        | Opcode::RdmaWriteOnlyWithImmediate
        | Opcode::RdmaReadRequest => fail_active_transport(slot, memory),
    }
}

fn handle_aeth_response<const MRS: usize, const SQ: usize, const RQ: usize, const CQ: usize>(
    slot: &mut RcQpSlot<SQ, RQ, CQ>,
    memory: &mut MemoryRegistry<'_, MRS>,
    aeth: Aeth,
    response_psn: Psn,
    now: u64,
    ticks_per_second: u64,
    stats: &mut RcEndpointStats,
) -> HandlerResult {
    match aeth.class() {
        AethClass::Ack { .. } => {
            let Some(active) = slot.active_request else {
                return HandlerResult::default();
            };
            if matches!(active.work.kind, WorkRequestKind::RdmaRead { .. }) {
                return fail_active_transport(slot, memory);
            }
            if active.transmitted_packets == 0
                || matches!(
                    response_psn.compare(
                        active
                            .first_psn
                            .wrapping_add(active.transmitted_packets - 1),
                    ),
                    rocev2_core::PsnOrdering::After
                )
            {
                return fail_active_transport(slot, memory);
            }
            match slot.send_window.acknowledge(response_psn) {
                AckAdvance::Advanced { .. } => {
                    if let Some(current) = slot.active_request.as_mut() {
                        current.retry_budget.reset();
                    }
                    if slot.send_window.oldest_unacknowledged() == active.last_psn.next() {
                        let completions = slot.finish_active(
                            memory,
                            CompletionStatus::Success,
                            active.work.sge.length,
                        );
                        HandlerResult {
                            reply: None,
                            completions,
                            retransmissions: 0,
                        }
                    } else {
                        if let Some(current) = slot.active_request.as_mut() {
                            let timeout =
                                ack_timeout_ticks(slot.machine.config().timeout, ticks_per_second)
                                    .unwrap_or(u64::MAX);
                            current.timer.arm(now, timeout);
                        }
                        HandlerResult::default()
                    }
                }
                AckAdvance::Duplicate => HandlerResult::default(),
                AckAdvance::Invalid => fail_active_transport(slot, memory),
            }
        }
        AethClass::RnrNak { timer } => {
            stats.rnr_naks = stats.rnr_naks.saturating_add(1);
            schedule_rnr_retry(slot, memory, timer, now, ticks_per_second, stats)
        }
        AethClass::Nak(NakCode::PsnSequenceError) => schedule_transport_retry(slot, memory, stats),
        AethClass::Nak(NakCode::InvalidRequest) => {
            fail_active_and_enter_error(slot, memory, CompletionStatus::RemoteInvalidRequest)
        }
        AethClass::Nak(NakCode::RemoteAccessError) => {
            fail_active_and_enter_error(slot, memory, CompletionStatus::RemoteAccessError)
        }
        AethClass::Nak(NakCode::RemoteOperationError | NakCode::Unknown(_))
        | AethClass::Reserved { .. } => {
            fail_active_and_enter_error(slot, memory, CompletionStatus::TransportError)
        }
    }
}

fn handle_read_response<const MRS: usize, const SQ: usize, const RQ: usize, const CQ: usize>(
    slot: &mut RcQpSlot<SQ, RQ, CQ>,
    memory: &mut MemoryRegistry<'_, MRS>,
    packet: PacketRef<'_>,
    now: u64,
    ticks_per_second: u64,
    stats: &mut RcEndpointStats,
) -> HandlerResult {
    let Some(active) = slot.active_request else {
        return HandlerResult::default();
    };
    if !matches!(active.work.kind, WorkRequestKind::RdmaRead { .. }) {
        return fail_active_transport(slot, memory);
    }

    if let Some(aeth) = packet.aeth {
        if !matches!(aeth.class(), AethClass::Ack { .. }) {
            return handle_aeth_response(
                slot,
                aeth,
                Psn::new_truncated(packet.bth.psn),
                now,
                ticks_per_second,
                stats,
            );
        }
    }

    let expected_psn = active.first_psn.wrapping_add(active.read_packets_received);
    let received_psn = Psn::new_truncated(packet.bth.psn);
    match received_psn.compare(expected_psn) {
        rocev2_core::PsnOrdering::Before | rocev2_core::PsnOrdering::After => {
            return HandlerResult::default();
        }
        rocev2_core::PsnOrdering::Equal => {}
    }

    let expected_opcode = segmented_opcode(
        TransferDirection::ReadResponse,
        active.read_packets_received,
        active.packet_count,
    );
    if packet.bth.opcode != expected_opcode {
        return fail_active_transport(slot, memory);
    }
    let Some((offset, expected_length)) = segment_bounds(
        active.work.sge.length,
        slot.machine.config().path_mtu.bytes(),
        active.read_packets_received,
    ) else {
        return fail_active_transport(slot, memory);
    };
    if packet.payload.len() != expected_length {
        return fail_active_transport(slot, memory);
    }
    let Some(local_address) = active
        .work
        .sge
        .address
        .checked_add(u64::try_from(offset).unwrap_or(u64::MAX))
    else {
        return fail_active_and_enter_error(slot, memory, CompletionStatus::LocalLengthError);
    };
    if memory
        .write_local(active.work.sge.lkey, local_address, packet.payload)
        .is_err()
    {
        return fail_active_and_enter_error(slot, memory, CompletionStatus::LocalProtectionError);
    }

    let _ack = slot.send_window.acknowledge(received_psn);
    let completed = active.read_packets_received + 1 == active.packet_count;
    if let Some(current) = slot.active_request.as_mut() {
        current.read_packets_received += 1;
        current.bytes_received = current
            .bytes_received
            .saturating_add(u32::try_from(packet.payload.len()).unwrap_or(u32::MAX));
        current.retry_budget.reset();
        if !completed {
            let timeout = ack_timeout_ticks(slot.machine.config().timeout, ticks_per_second)
                .unwrap_or(u64::MAX);
            current.timer.arm(now, timeout);
        }
    }

    if completed {
        let byte_len = active.work.sge.length;
        let completions = slot.finish_active(memory, CompletionStatus::Success, byte_len);
        HandlerResult {
            reply: None,
            completions,
            retransmissions: 0,
        }
    } else {
        HandlerResult::default()
    }
}

fn schedule_transport_retry<const MRS: usize, const SQ: usize, const RQ: usize, const CQ: usize>(
    slot: &mut RcQpSlot<SQ, RQ, CQ>,
    memory: &mut MemoryRegistry<'_, MRS>,
    stats: &mut RcEndpointStats,
) -> HandlerResult {
    let Some(active) = slot.active_request.as_mut() else {
        return HandlerResult::default();
    };
    match active.retry_budget.on_failure(RetryReason::Timeout, 0) {
        RetryDecision::Retry { .. } => {
            active.reset_for_retry();
            stats.retransmissions = stats.retransmissions.saturating_add(1);
            HandlerResult {
                reply: None,
                completions: 0,
                retransmissions: 1,
            }
        }
        RetryDecision::Exhausted { .. } => {
            fail_active_and_enter_error(slot, memory, CompletionStatus::RetryExceeded)
        }
    }
}

fn schedule_rnr_retry<const MRS: usize, const SQ: usize, const RQ: usize, const CQ: usize>(
    slot: &mut RcQpSlot<SQ, RQ, CQ>,
    memory: &mut MemoryRegistry<'_, MRS>,
    timer_code: u8,
    now: u64,
    ticks_per_second: u64,
    _stats: &mut RcEndpointStats,
) -> HandlerResult {
    let delay = rnr_timer_ticks(timer_code, ticks_per_second).unwrap_or(u64::MAX);
    let Some(active) = slot.active_request.as_mut() else {
        return HandlerResult::default();
    };
    match active
        .retry_budget
        .on_failure(RetryReason::ReceiverNotReady, delay)
    {
        RetryDecision::Retry { delay_ticks } => {
            active.phase = RequestPhase::RnrWait;
            active.timer.arm(now, delay_ticks);
            HandlerResult::default()
        }
        RetryDecision::Exhausted { .. } => {
            fail_active_and_enter_error(slot, memory, CompletionStatus::RnrRetryExceeded)
        }
    }
}

fn fail_active_transport<const MRS: usize, const SQ: usize, const RQ: usize, const CQ: usize>(
    slot: &mut RcQpSlot<SQ, RQ, CQ>,
    memory: &mut MemoryRegistry<'_, MRS>,
) -> HandlerResult {
    fail_active_and_enter_error(slot, memory, CompletionStatus::TransportError)
}

fn fail_active_and_enter_error<
    const MRS: usize,
    const SQ: usize,
    const RQ: usize,
    const CQ: usize,
>(
    slot: &mut RcQpSlot<SQ, RQ, CQ>,
    memory: &mut MemoryRegistry<'_, MRS>,
    status: CompletionStatus,
) -> HandlerResult {
    let completions = fail_active_and_error(slot, memory, status);
    HandlerResult {
        reply: None,
        completions,
        retransmissions: 0,
    }
}

fn fail_active_and_error<const MRS: usize, const SQ: usize, const RQ: usize, const CQ: usize>(
    slot: &mut RcQpSlot<SQ, RQ, CQ>,
    memory: &mut MemoryRegistry<'_, MRS>,
    status: CompletionStatus,
) -> usize {
    let mut completions = slot.finish_active(memory, status, 0);
    completions += slot.enter_error(memory);
    completions
}
