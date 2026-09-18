//! Linux `AF_XDP` packet backend.

use crate::ethernet::{
    ETHERNET_HEADER_LEN, EthernetFrameError, EthernetPath, ipv4_payload, write_ipv4_header,
};
use crate::{PacketBatchIo, PacketIo, SubmitError, TxPacket};
use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;
use core::mem::{MaybeUninit, align_of, size_of};
use core::ptr::{self, NonNull};
use core::slice;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicU32, Ordering};

static NEXT_SOCKET_ID: AtomicU32 = AtomicU32::new(1);

const UMEM_FRAME_2K: u32 = 2048;
const UMEM_FRAME_4K: u32 = 4096;
const DEFAULT_FRAME_COUNT: u32 = 4096;
const DEFAULT_TX_FRAME_COUNT: u32 = 1024;
const DEFAULT_RX_RING_SIZE: u32 = 2048;
const DEFAULT_TX_RING_SIZE: u32 = 1024;
const DEFAULT_FILL_RING_SIZE: u32 = 4096;
const DEFAULT_COMPLETION_RING_SIZE: u32 = 1024;

/// `AF_XDP` bind behavior for zero-copy and copy mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AfxdpBindMode {
    /// Require driver zero-copy support or fail the bind.
    ZeroCopy,
    /// Require copy mode.
    Copy,
    /// Permit the kernel to fall back from zero-copy to copy mode.
    AllowCopyFallback,
}

impl AfxdpBindMode {
    const fn bind_flags(self) -> u16 {
        match self {
            Self::ZeroCopy => libc::XDP_ZEROCOPY,
            Self::Copy => libc::XDP_COPY,
            Self::AllowCopyFallback => 0,
        }
    }
}

/// UMEM mapping policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UmemBacking {
    /// Use regular anonymous memory populated during construction.
    Regular,
    /// Request Linux hugetlb-backed anonymous memory.
    HugePages,
}

/// `AF_XDP` socket and UMEM configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AfxdpConfig {
    /// Linux interface index.
    pub interface_index: u32,
    /// Hardware receive queue bound to this socket.
    pub queue_id: u32,
    /// Layer-2 path used for transmit frames.
    pub ethernet_path: EthernetPath,
    /// UMEM chunk size. Only aligned 2 KiB and 4 KiB chunks are supported.
    pub frame_size: u32,
    /// Total UMEM frame count.
    pub frame_count: u32,
    /// Frames reserved exclusively for transmit ownership.
    pub tx_frame_count: u32,
    /// Per-frame UMEM headroom requested from the kernel.
    pub headroom: u32,
    /// RX descriptor ring size.
    pub rx_ring_size: u32,
    /// TX descriptor ring size.
    pub tx_ring_size: u32,
    /// UMEM fill ring size.
    pub fill_ring_size: u32,
    /// UMEM completion ring size.
    pub completion_ring_size: u32,
    /// Zero-copy/copy bind policy.
    pub bind_mode: AfxdpBindMode,
    /// UMEM allocation policy.
    pub umem_backing: UmemBacking,
}

impl AfxdpConfig {
    /// Create a zero-copy-first configuration for one interface queue.
    #[must_use]
    pub const fn new(interface_index: u32, queue_id: u32, ethernet_path: EthernetPath) -> Self {
        Self {
            interface_index,
            queue_id,
            ethernet_path,
            frame_size: UMEM_FRAME_4K,
            frame_count: DEFAULT_FRAME_COUNT,
            tx_frame_count: DEFAULT_TX_FRAME_COUNT,
            headroom: 0,
            rx_ring_size: DEFAULT_RX_RING_SIZE,
            tx_ring_size: DEFAULT_TX_RING_SIZE,
            fill_ring_size: DEFAULT_FILL_RING_SIZE,
            completion_ring_size: DEFAULT_COMPLETION_RING_SIZE,
            bind_mode: AfxdpBindMode::ZeroCopy,
            umem_backing: UmemBacking::Regular,
        }
    }
}

/// Generation-checked `AF_XDP` receive frame handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AfxdpRxFrame {
    owner: u32,
    index: u32,
    generation: u64,
    ipv4_offset: u32,
    ipv4_length: u32,
}

/// Generation-checked `AF_XDP` transmit frame handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AfxdpTxFrame {
    owner: u32,
    index: u32,
    generation: u64,
}

/// `AF_XDP` backend counters maintained without allocation or locking.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AfxdpStatistics {
    /// RX descriptors rejected before exposure to the transport.
    pub invalid_rx_descriptors: u64,
    /// Ethernet frames rejected because they were VLAN or `QinQ` tagged.
    pub vlan_frames: u64,
    /// Non-IPv4 Ethernet frames rejected by the backend.
    pub non_ipv4_frames: u64,
    /// Ethernet frames with malformed IPv4 headers.
    pub invalid_ipv4_frames: u64,
    /// RX wakeup syscalls that returned an error.
    pub rx_wakeup_errors: u64,
    /// TX wakeup syscalls that returned an error.
    pub tx_wakeup_errors: u64,
    /// TX frames returned by the completion ring, not RC delivery acknowledgements.
    pub reclaimed_tx_frames: u64,
    /// Completion addresses that do not identify an outstanding TX descriptor.
    pub invalid_completions: u64,
    /// Frames retired instead of allowing a generation identifier to wrap.
    pub retired_frames: u64,
}

/// Kernel-provided `AF_XDP` socket counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AfxdpKernelStatistics {
    /// Packets dropped for reasons other than an invalid descriptor.
    pub rx_dropped: u64,
    /// Invalid RX descriptors observed by the kernel.
    pub rx_invalid_descriptors: u64,
    /// Invalid TX descriptors observed by the kernel.
    pub tx_invalid_descriptors: u64,
    /// RX packets dropped because the RX ring was full.
    pub rx_ring_full: u64,
    /// RX packets dropped because the fill ring had no descriptors.
    pub rx_fill_ring_empty: u64,
    /// TX opportunities with an empty TX ring.
    pub tx_ring_empty: u64,
}

/// `AF_XDP` backend error.
#[derive(Debug)]
pub enum AfxdpError {
    /// Linux system call failure.
    Io(io::Error),
    /// Invalid static backend configuration.
    InvalidConfig(&'static str),
    /// Kernel `AF_XDP` ring layout is unsupported or malformed.
    InvalidKernelLayout,
    /// A shared ring producer/consumer distance exceeded its capacity.
    CorruptRing,
    /// The completion ring returned a foreign, duplicate, or invalid address.
    CorruptCompletion,
    /// A socket or frame identity would wrap and invalidate stale-handle protection.
    IdentityExhausted,
    /// A caller supplied an occupied batch output slot.
    OutputSlotOccupied,
    /// A receive frame is stale, duplicated, or not application-owned.
    InvalidReceiveFrame,
    /// A transmit frame is stale, duplicated, or not application-owned.
    InvalidTransmitFrame,
    /// A transmit packet has no frame handle.
    MissingTransmitFrame,
    /// A complete IPv4 packet exceeds the configured frame payload.
    PacketTooLarge {
        /// Packet byte length.
        length: usize,
        /// Maximum complete IPv4 packet length.
        maximum: usize,
    },
    /// A scalar receive buffer cannot hold the packet.
    OutputTooSmall {
        /// Required packet length.
        required: usize,
        /// Caller buffer length.
        available: usize,
    },
    /// A transmit buffer does not contain one complete IPv4 packet.
    InvalidIpv4Packet,
    /// A scalar transmit could not acquire a frame or TX descriptor.
    WouldBlock,
}

impl fmt::Display for AfxdpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "AF_XDP system call failed: {error}"),
            Self::InvalidConfig(reason) => {
                write!(formatter, "invalid AF_XDP configuration: {reason}")
            }
            Self::InvalidKernelLayout => formatter.write_str("invalid AF_XDP kernel ring layout"),
            Self::CorruptRing => {
                formatter.write_str("AF_XDP ring producer/consumer state is corrupt")
            }
            Self::CorruptCompletion => formatter.write_str("invalid AF_XDP completion address"),
            Self::IdentityExhausted => formatter.write_str("AF_XDP identity space exhausted"),
            Self::OutputSlotOccupied => {
                formatter.write_str("batch output slot is already occupied")
            }
            Self::InvalidReceiveFrame => formatter.write_str("invalid AF_XDP receive frame"),
            Self::InvalidTransmitFrame => formatter.write_str("invalid AF_XDP transmit frame"),
            Self::MissingTransmitFrame => {
                formatter.write_str("transmit packet has no AF_XDP frame")
            }
            Self::PacketTooLarge { length, maximum } => {
                write!(
                    formatter,
                    "IPv4 packet length {length} exceeds AF_XDP maximum {maximum}"
                )
            }
            Self::OutputTooSmall {
                required,
                available,
            } => write!(
                formatter,
                "receive buffer length {available} is smaller than AF_XDP packet {required}"
            ),
            Self::InvalidIpv4Packet => formatter.write_str("invalid complete IPv4 packet"),
            Self::WouldBlock => formatter.write_str("AF_XDP transmit path is temporarily full"),
        }
    }
}

impl std::error::Error for AfxdpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for AfxdpError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FrameState {
    FillRing,
    AppRx,
    FreeTx,
    AppTx,
    TxRing,
    Lost,
}

#[derive(Clone, Copy, Debug)]
enum FatalError {
    Completion,
    Identity,
    System(i32),
}

#[derive(Clone, Copy, Debug)]
struct FrameMeta {
    generation: u64,
    state: FrameState,
    seen_epoch: u64,
}

#[derive(Debug)]
struct Mapping {
    pointer: NonNull<u8>,
    length: usize,
}

impl Mapping {
    fn anonymous(length: usize, backing: UmemBacking) -> io::Result<Self> {
        let mut flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE;
        if backing == UmemBacking::HugePages {
            flags |= libc::MAP_HUGETLB;
        }

        // safety: mmap receives no borrowed pointer and returns an owned mapping on success.
        let pointer = unsafe {
            libc::mmap(
                ptr::null_mut(),
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                flags,
                -1,
                0,
            )
        };
        if pointer == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let pointer = NonNull::new(pointer.cast::<u8>())
            .ok_or_else(|| io::Error::other("mmap returned a null mapping"))?;
        Ok(Self { pointer, length })
    }

    fn shared(descriptor: i32, length: usize, offset: libc::off_t) -> io::Result<Self> {
        // safety: the fd owns an AF_XDP ring mapping and the returned mapping is owned here.
        let pointer = unsafe {
            libc::mmap(
                ptr::null_mut(),
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                descriptor,
                offset,
            )
        };
        if pointer == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let pointer = NonNull::new(pointer.cast::<u8>())
            .ok_or_else(|| io::Error::other("mmap returned a null mapping"))?;
        Ok(Self { pointer, length })
    }

    const fn length(&self) -> usize {
        self.length
    }

    const fn pointer(&self) -> NonNull<u8> {
        self.pointer
    }
}

// safety: mapping ownership moves with the backend and no userspace alias escapes it.
unsafe impl Send for Mapping {}

impl Drop for Mapping {
    fn drop(&mut self) {
        // safety: pointer and length are exactly the live mapping created by mmap.
        let _ = unsafe { libc::munmap(self.pointer.as_ptr().cast(), self.length) };
    }
}

#[derive(Debug)]
struct Umem {
    mapping: Mapping,
    frame_size: usize,
    frame_count: usize,
    headroom: usize,
}

impl Umem {
    fn new(config: AfxdpConfig) -> Result<Self, AfxdpError> {
        let frame_size = usize::try_from(config.frame_size)
            .map_err(|_| AfxdpError::InvalidConfig("frame size does not fit usize"))?;
        let frame_count = usize::try_from(config.frame_count)
            .map_err(|_| AfxdpError::InvalidConfig("frame count does not fit usize"))?;
        let length = frame_size
            .checked_mul(frame_count)
            .ok_or(AfxdpError::InvalidConfig("UMEM length overflows usize"))?;
        let mapping = Mapping::anonymous(length, config.umem_backing)?;
        let page_size = system_page_size()?;
        if mapping.pointer().as_ptr() as usize % page_size != 0 {
            return Err(AfxdpError::InvalidKernelLayout);
        }
        Ok(Self {
            mapping,
            frame_size,
            frame_count,
            headroom: usize::try_from(config.headroom)
                .map_err(|_| AfxdpError::InvalidConfig("headroom does not fit usize"))?,
        })
    }

    fn registration(&self) -> libc::xdp_umem_reg {
        libc::xdp_umem_reg {
            addr: self.mapping.pointer().as_ptr() as usize as u64,
            len: self.mapping.length() as u64,
            chunk_size: self.frame_size as u32,
            headroom: self.headroom as u32,
            flags: 0,
            tx_metadata_len: 0,
        }
    }

    const fn frame_base(&self, index: usize) -> usize {
        index * self.frame_size
    }

    fn frame_address(&self, index: usize) -> u64 {
        self.frame_base(index) as u64
    }

    fn frame_index_for_range(&self, address: u64, length: u32) -> Option<(usize, usize)> {
        let address = usize::try_from(address).ok()?;
        let length = usize::try_from(length).ok()?;
        let end = address.checked_add(length)?;
        if address >= self.mapping.length() || end > self.mapping.length() || length == 0 {
            return None;
        }
        let index = address / self.frame_size;
        if index >= self.frame_count {
            return None;
        }
        let base = self.frame_base(index);
        if end > base + self.frame_size {
            return None;
        }
        Some((index, address - base))
    }

    fn bytes(&self, offset: usize, length: usize) -> &[u8] {
        debug_assert!(offset <= self.mapping.length());
        debug_assert!(length <= self.mapping.length() - offset);
        // safety: validated offsets stay inside the live UMEM mapping for this shared borrow.
        unsafe { slice::from_raw_parts(self.mapping.pointer().as_ptr().add(offset), length) }
    }

    fn bytes_mut(&mut self, offset: usize, length: usize) -> &mut [u8] {
        debug_assert!(offset <= self.mapping.length());
        debug_assert!(length <= self.mapping.length() - offset);
        // safety: frame ownership plus &mut self guarantees unique writable access to this range.
        unsafe { slice::from_raw_parts_mut(self.mapping.pointer().as_ptr().add(offset), length) }
    }
}

#[derive(Debug)]
struct RingMemory<T> {
    _mapping: Mapping,
    producer: NonNull<AtomicU32>,
    consumer: NonNull<AtomicU32>,
    flags: NonNull<AtomicU32>,
    descriptors: NonNull<T>,
    size: u32,
    mask: u32,
}

impl<T> RingMemory<T> {
    fn map(
        descriptor: i32,
        offsets: &libc::xdp_ring_offset,
        entries: u32,
        page_offset: libc::off_t,
    ) -> Result<Self, AfxdpError> {
        let length = ring_mapping_length::<T>(offsets, entries)?;
        let mapping = Mapping::shared(descriptor, length, page_offset)?;
        let producer = mapped_pointer::<AtomicU32>(&mapping, offsets.producer)?;
        let consumer = mapped_pointer::<AtomicU32>(&mapping, offsets.consumer)?;
        let flags = mapped_pointer::<AtomicU32>(&mapping, offsets.flags)?;
        let descriptors = mapped_pointer::<T>(&mapping, offsets.desc)?;

        Ok(Self {
            _mapping: mapping,
            producer,
            consumer,
            flags,
            descriptors,
            size: entries,
            mask: entries - 1,
        })
    }

    fn producer(&self) -> &AtomicU32 {
        // safety: constructor validated alignment and range for the mapping lifetime.
        unsafe { self.producer.as_ref() }
    }

    fn consumer(&self) -> &AtomicU32 {
        // safety: constructor validated alignment and range for the mapping lifetime.
        unsafe { self.consumer.as_ref() }
    }

    fn flags(&self) -> &AtomicU32 {
        // safety: constructor validated alignment and range for the mapping lifetime.
        unsafe { self.flags.as_ref() }
    }

    fn descriptor_pointer(&self, index: u32) -> *mut T {
        let slot = (index & self.mask) as usize;
        // safety: mask constrains the descriptor index to the mapped ring capacity.
        unsafe { self.descriptors.as_ptr().add(slot) }
    }
}

// safety: ring memory is SPSC and the backend transfers only exclusive ownership across threads.
unsafe impl<T: Send> Send for RingMemory<T> {}

#[derive(Debug)]
struct ProducerRing<T> {
    memory: RingMemory<T>,
}

impl<T: Copy> ProducerRing<T> {
    fn map(
        descriptor: i32,
        offsets: &libc::xdp_ring_offset,
        entries: u32,
        page_offset: libc::off_t,
    ) -> Result<Self, AfxdpError> {
        Ok(Self {
            memory: RingMemory::map(descriptor, offsets, entries, page_offset)?,
        })
    }

    fn reserve(&self, requested: u32) -> Result<(u32, u32), AfxdpError> {
        let producer = self.memory.producer().load(Ordering::Relaxed);
        let consumer = self.memory.consumer().load(Ordering::Acquire);
        let used = producer.wrapping_sub(consumer);
        if used > self.memory.size {
            return Err(AfxdpError::CorruptRing);
        }
        let available = self.memory.size - used;
        Ok((producer, requested.min(available)))
    }

    fn write(&mut self, index: u32, value: T) {
        // safety: the caller reserved this producer-owned descriptor before publishing it.
        unsafe { ptr::write_volatile(self.memory.descriptor_pointer(index), value) };
    }

    fn submit(&self, start: u32, count: u32) {
        if count == 0 {
            return;
        }
        debug_assert_eq!(self.memory.producer().load(Ordering::Relaxed), start);
        self.memory
            .producer()
            .store(start.wrapping_add(count), Ordering::Release);
    }

    fn needs_wakeup(&self) -> bool {
        self.memory.flags().load(Ordering::Acquire) & libc::XDP_RING_NEED_WAKEUP != 0
    }
}

#[derive(Debug)]
struct ConsumerRing<T> {
    memory: RingMemory<T>,
}

impl<T: Copy> ConsumerRing<T> {
    fn map(
        descriptor: i32,
        offsets: &libc::xdp_ring_offset,
        entries: u32,
        page_offset: libc::off_t,
    ) -> Result<Self, AfxdpError> {
        Ok(Self {
            memory: RingMemory::map(descriptor, offsets, entries, page_offset)?,
        })
    }

    fn peek(&self, requested: u32) -> Result<(u32, u32), AfxdpError> {
        let consumer = self.memory.consumer().load(Ordering::Relaxed);
        let producer = self.memory.producer().load(Ordering::Acquire);
        let available = producer.wrapping_sub(consumer);
        if available > self.memory.size {
            return Err(AfxdpError::CorruptRing);
        }
        Ok((consumer, requested.min(available)))
    }

    fn read(&self, index: u32) -> T {
        // safety: the caller only reads descriptors made visible by the kernel producer index.
        unsafe { ptr::read_volatile(self.memory.descriptor_pointer(index)) }
    }

    fn release(&self, start: u32, count: u32) {
        if count == 0 {
            return;
        }
        debug_assert_eq!(self.memory.consumer().load(Ordering::Relaxed), start);
        self.memory
            .consumer()
            .store(start.wrapping_add(count), Ordering::Release);
    }
}

/// One queue-bound nonblocking Linux `AF_XDP` socket.
///
/// Construction allocates and registers UMEM, maps all four `AF_XDP` rings,
/// seeds the fill ring, and binds with `XDP_USE_NEED_WAKEUP`. Steady-state
/// receive, transmit, recycling, and completion processing do not allocate.
/// An XDP program must steer matching traffic to this socket separately.
#[derive(Debug)]
pub struct AfxdpSocket {
    // Unregister queue steering before closing the socket or releasing UMEM.
    steering: Option<crate::xdp::QueueRegistration>,
    owner: u32,
    fatal_error: Option<FatalError>,
    descriptor: OwnedFd,
    rx_ring: ConsumerRing<libc::xdp_desc>,
    tx_ring: ProducerRing<libc::xdp_desc>,
    fill_ring: ProducerRing<u64>,
    completion_ring: ConsumerRing<u64>,
    umem: Umem,
    frames: Vec<FrameMeta>,
    tx_free: Vec<u32>,
    rx_frame_count: usize,
    maximum_ipv4_packet: usize,
    config: AfxdpConfig,
    zero_copy: bool,
    validation_epoch: u64,
    statistics: AfxdpStatistics,
    _single_owner: PhantomData<Cell<()>>,
}

impl AfxdpSocket {
    /// Create and bind an `AF_XDP` socket to one interface queue.
    pub fn bind(config: AfxdpConfig) -> Result<Self, AfxdpError> {
        let validated = ValidatedConfig::new(config)?;
        let owner = NEXT_SOCKET_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| AfxdpError::IdentityExhausted)?;
        let descriptor = create_xdp_socket()?;
        let umem = Umem::new(config)?;
        register_umem(descriptor.as_raw_fd(), &umem)?;
        configure_ring(
            descriptor.as_raw_fd(),
            libc::XDP_UMEM_FILL_RING,
            config.fill_ring_size,
        )?;
        configure_ring(
            descriptor.as_raw_fd(),
            libc::XDP_UMEM_COMPLETION_RING,
            config.completion_ring_size,
        )?;
        configure_ring(
            descriptor.as_raw_fd(),
            libc::XDP_RX_RING,
            config.rx_ring_size,
        )?;
        configure_ring(
            descriptor.as_raw_fd(),
            libc::XDP_TX_RING,
            config.tx_ring_size,
        )?;

        let offsets = mmap_offsets(descriptor.as_raw_fd())?;
        let rx_ring = ConsumerRing::map(
            descriptor.as_raw_fd(),
            &offsets.rx,
            config.rx_ring_size,
            libc::XDP_PGOFF_RX_RING,
        )?;
        let tx_ring = ProducerRing::map(
            descriptor.as_raw_fd(),
            &offsets.tx,
            config.tx_ring_size,
            libc::XDP_PGOFF_TX_RING,
        )?;
        let fill_offset = libc::off_t::try_from(libc::XDP_UMEM_PGOFF_FILL_RING)
            .map_err(|_| AfxdpError::InvalidKernelLayout)?;
        let completion_offset = libc::off_t::try_from(libc::XDP_UMEM_PGOFF_COMPLETION_RING)
            .map_err(|_| AfxdpError::InvalidKernelLayout)?;
        let fill_ring = ProducerRing::map(
            descriptor.as_raw_fd(),
            &offsets.fr,
            config.fill_ring_size,
            fill_offset,
        )?;
        let completion_ring = ConsumerRing::map(
            descriptor.as_raw_fd(),
            &offsets.cr,
            config.completion_ring_size,
            completion_offset,
        )?;

        let mut frames = Vec::with_capacity(validated.frame_count);
        for index in 0..validated.frame_count {
            frames.push(FrameMeta {
                generation: 0,
                state: if index < validated.rx_frame_count {
                    FrameState::FillRing
                } else {
                    FrameState::FreeTx
                },
                seen_epoch: 0,
            });
        }

        let mut tx_free = Vec::with_capacity(validated.tx_frame_count);
        for index in validated.rx_frame_count..validated.frame_count {
            tx_free.push(index as u32);
        }

        let mut backend = Self {
            steering: None,
            owner,
            fatal_error: None,
            descriptor,
            rx_ring,
            tx_ring,
            fill_ring,
            completion_ring,
            umem,
            frames,
            tx_free,
            rx_frame_count: validated.rx_frame_count,
            maximum_ipv4_packet: validated.maximum_ipv4_packet,
            config,
            zero_copy: false,
            validation_epoch: 0,
            statistics: AfxdpStatistics::default(),
            _single_owner: PhantomData,
        };
        backend.seed_fill_ring()?;
        backend.bind_socket()?;
        backend.zero_copy = socket_zero_copy(backend.descriptor.as_raw_fd())?;
        match config.bind_mode {
            AfxdpBindMode::ZeroCopy if !backend.zero_copy => {
                return Err(AfxdpError::InvalidKernelLayout);
            }
            AfxdpBindMode::Copy if backend.zero_copy => {
                return Err(AfxdpError::InvalidKernelLayout);
            }
            _ => {}
        }
        backend.wake_rx_if_needed();
        backend.check_health()?;
        Ok(backend)
    }

    /// Register this bound socket in its interface's XSKMAP.
    ///
    /// The socket retains the map and program until it is detached or dropped.
    /// A live queue registration is never replaced, even by another socket.
    pub fn attach_steering(&mut self, steering: &crate::XdpSteering) -> Result<(), AfxdpError> {
        self.check_health()?;
        if self.steering.is_some() {
            return Err(AfxdpError::InvalidConfig(
                "socket already registered in XSKMAP",
            ));
        }
        self.steering = Some(steering.register(
            self.config.interface_index,
            self.config.queue_id,
            self.descriptor.as_raw_fd(),
        )?);
        Ok(())
    }

    /// Remove ingress steering while retaining socket, outstanding TX, and UMEM ownership.
    pub fn detach_steering(&mut self) -> Result<(), AfxdpError> {
        if let Some(registration) = &mut self.steering {
            registration.unregister()?;
        }
        self.steering = None;
        Ok(())
    }

    fn check_health(&self) -> Result<(), AfxdpError> {
        match self.fatal_error {
            None => Ok(()),
            Some(FatalError::Completion) => Err(AfxdpError::CorruptCompletion),
            Some(FatalError::Identity) => Err(AfxdpError::IdentityExhausted),
            Some(FatalError::System(errno)) => {
                Err(AfxdpError::Io(io::Error::from_raw_os_error(errno)))
            }
        }
    }

    fn retire_frame(&mut self, index: usize) {
        self.frames[index].state = FrameState::Lost;
        self.statistics.retired_frames = self.statistics.retired_frames.saturating_add(1);
        self.fatal_error.get_or_insert(FatalError::Identity);
    }

    /// Return the configuration used to construct this socket.
    #[must_use]
    pub const fn config(&self) -> AfxdpConfig {
        self.config
    }

    /// Return whether the bound socket is operating in driver zero-copy mode.
    #[must_use]
    pub const fn is_zero_copy(&self) -> bool {
        self.zero_copy
    }

    /// Return backend-maintained packet and wakeup counters.
    #[must_use]
    pub const fn statistics(&self) -> AfxdpStatistics {
        self.statistics
    }

    /// Query the kernel's `AF_XDP` socket counters.
    pub fn kernel_statistics(&self) -> Result<AfxdpKernelStatistics, AfxdpError> {
        let statistics = xdp_kernel_statistics(self.descriptor.as_raw_fd())?;
        Ok(AfxdpKernelStatistics {
            rx_dropped: statistics.rx_dropped,
            rx_invalid_descriptors: statistics.rx_invalid_descs,
            tx_invalid_descriptors: statistics.tx_invalid_descs,
            rx_ring_full: statistics.rx_ring_full,
            rx_fill_ring_empty: statistics.rx_fill_ring_empty_descs,
            tx_ring_empty: statistics.tx_ring_empty_descs,
        })
    }

    fn seed_fill_ring(&mut self) -> Result<(), AfxdpError> {
        let requested = u32::try_from(self.rx_frame_count)
            .map_err(|_| AfxdpError::InvalidConfig("RX frame count exceeds u32"))?;
        let (start, count) = self.fill_ring.reserve(requested)?;
        if count != requested {
            return Err(AfxdpError::InvalidConfig(
                "fill ring cannot hold all initial RX frames",
            ));
        }
        for offset in 0..count {
            self.fill_ring.write(
                start.wrapping_add(offset),
                self.umem.frame_address(offset as usize),
            );
        }
        self.fill_ring.submit(start, count);
        Ok(())
    }

    fn bind_socket(&self) -> Result<(), AfxdpError> {
        let address = libc::sockaddr_xdp {
            sxdp_family: libc::AF_XDP as u16,
            sxdp_flags: self.config.bind_mode.bind_flags() | libc::XDP_USE_NEED_WAKEUP,
            sxdp_ifindex: self.config.interface_index,
            sxdp_queue_id: self.config.queue_id,
            sxdp_shared_umem_fd: 0,
        };
        let length = libc::socklen_t::try_from(size_of::<libc::sockaddr_xdp>())
            .map_err(|_| AfxdpError::InvalidKernelLayout)?;
        // safety: address is a fully initialized sockaddr_xdp with its exact byte length.
        let result = unsafe {
            libc::bind(
                self.descriptor.as_raw_fd(),
                (&raw const address).cast(),
                length,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn next_validation_epoch(&mut self) -> u64 {
        self.validation_epoch = self.validation_epoch.wrapping_add(1);
        if self.validation_epoch == 0 {
            for frame in &mut self.frames {
                frame.seen_epoch = 0;
            }
            self.validation_epoch = 1;
        }
        self.validation_epoch
    }

    fn validate_receive_handles(
        &mut self,
        frames: &[Option<AfxdpRxFrame>],
    ) -> Result<usize, AfxdpError> {
        let epoch = self.next_validation_epoch();
        let mut count = 0;
        for frame in frames.iter().flatten() {
            let index =
                usize::try_from(frame.index).map_err(|_| AfxdpError::InvalidReceiveFrame)?;
            let Some(metadata) = self.frames.get_mut(index) else {
                return Err(AfxdpError::InvalidReceiveFrame);
            };
            if frame.owner != self.owner
                || metadata.state != FrameState::AppRx
                || metadata.generation != frame.generation
                || metadata.seen_epoch == epoch
            {
                return Err(AfxdpError::InvalidReceiveFrame);
            }
            if metadata.generation == u64::MAX {
                return Err(AfxdpError::IdentityExhausted);
            }
            metadata.seen_epoch = epoch;
            count += 1;
        }
        Ok(count)
    }

    fn validate_transmit_handles(
        &mut self,
        frames: &[Option<AfxdpTxFrame>],
    ) -> Result<usize, AfxdpError> {
        let epoch = self.next_validation_epoch();
        let mut count = 0;
        for frame in frames.iter().flatten() {
            let index =
                usize::try_from(frame.index).map_err(|_| AfxdpError::InvalidTransmitFrame)?;
            let Some(metadata) = self.frames.get_mut(index) else {
                return Err(AfxdpError::InvalidTransmitFrame);
            };
            if frame.owner != self.owner
                || metadata.state != FrameState::AppTx
                || metadata.generation != frame.generation
                || metadata.seen_epoch == epoch
            {
                return Err(AfxdpError::InvalidTransmitFrame);
            }
            if metadata.generation == u64::MAX {
                return Err(AfxdpError::IdentityExhausted);
            }
            metadata.seen_epoch = epoch;
            count += 1;
        }
        Ok(count)
    }

    fn valid_rx_frame(&self, frame: AfxdpRxFrame) -> Option<usize> {
        let index = usize::try_from(frame.index).ok()?;
        let metadata = self.frames.get(index)?;
        (frame.owner == self.owner
            && metadata.state == FrameState::AppRx
            && metadata.generation == frame.generation)
            .then_some(index)
    }

    fn valid_tx_frame(&self, frame: AfxdpTxFrame) -> Option<usize> {
        let index = usize::try_from(frame.index).ok()?;
        let metadata = self.frames.get(index)?;
        (frame.owner == self.owner
            && metadata.state == FrameState::AppTx
            && metadata.generation == frame.generation)
            .then_some(index)
    }

    fn receive_descriptor(&mut self, descriptor: libc::xdp_desc) -> (Option<AfxdpRxFrame>, bool) {
        if descriptor.options != 0 {
            self.statistics.invalid_rx_descriptors =
                self.statistics.invalid_rx_descriptors.saturating_add(1);
            let refilled = self.recycle_dropped_descriptor(descriptor.addr, descriptor.len);
            return (None, refilled);
        }
        let Some((index, offset)) = self
            .umem
            .frame_index_for_range(descriptor.addr, descriptor.len)
        else {
            self.statistics.invalid_rx_descriptors =
                self.statistics.invalid_rx_descriptors.saturating_add(1);
            return (None, false);
        };
        if index >= self.rx_frame_count || self.frames[index].state != FrameState::FillRing {
            self.statistics.invalid_rx_descriptors =
                self.statistics.invalid_rx_descriptors.saturating_add(1);
            return (None, false);
        }

        let frame_base = self.umem.frame_base(index);
        let ipv4_payload_result = {
            let frame = self
                .umem
                .bytes(frame_base + offset, descriptor.len as usize);
            ipv4_payload(frame).map(<[u8]>::len)
        };
        let ipv4_length = match ipv4_payload_result {
            Ok(length) => length,
            Err(error) => {
                match error {
                    EthernetFrameError::VlanUnsupported => {
                        self.statistics.vlan_frames = self.statistics.vlan_frames.saturating_add(1);
                    }
                    EthernetFrameError::NonIpv4 => {
                        self.statistics.non_ipv4_frames =
                            self.statistics.non_ipv4_frames.saturating_add(1);
                    }
                    EthernetFrameError::Truncated | EthernetFrameError::InvalidIpv4 => {
                        self.statistics.invalid_ipv4_frames =
                            self.statistics.invalid_ipv4_frames.saturating_add(1);
                    }
                }
                let refilled = self.return_rx_index_to_fill(index);
                return (None, refilled);
            }
        };

        let ipv4_offset = offset + ETHERNET_HEADER_LEN;
        let generation = self.frames[index].generation;
        self.frames[index].state = FrameState::AppRx;
        (
            Some(AfxdpRxFrame {
                owner: self.owner,
                index: index as u32,
                generation,
                ipv4_offset: ipv4_offset as u32,
                ipv4_length: ipv4_length as u32,
            }),
            false,
        )
    }

    fn recycle_dropped_descriptor(&mut self, address: u64, length: u32) -> bool {
        let Some((index, _)) = self.umem.frame_index_for_range(address, length) else {
            return false;
        };
        if index < self.rx_frame_count && self.frames[index].state == FrameState::FillRing {
            return self.return_rx_index_to_fill(index);
        }
        false
    }

    fn return_rx_index_to_fill(&mut self, index: usize) -> bool {
        let Ok((start, count)) = self.fill_ring.reserve(1) else {
            self.frames[index].state = FrameState::Lost;
            return false;
        };
        if count != 1 {
            self.frames[index].state = FrameState::Lost;
            return false;
        }
        let Some(generation) = self.frames[index].generation.checked_add(1) else {
            self.retire_frame(index);
            return false;
        };
        self.frames[index].generation = generation;
        self.frames[index].state = FrameState::FillRing;
        self.fill_ring.write(start, self.umem.frame_address(index));
        self.fill_ring.submit(start, 1);
        true
    }

    fn validate_tx_packet(
        &mut self,
        packet: &TxPacket<AfxdpTxFrame>,
        epoch: u64,
    ) -> Result<(), AfxdpError> {
        let Some(frame) = packet.frame().copied() else {
            return Err(AfxdpError::MissingTransmitFrame);
        };
        let index = usize::try_from(frame.index).map_err(|_| AfxdpError::InvalidTransmitFrame)?;
        let Some(metadata) = self.frames.get_mut(index) else {
            return Err(AfxdpError::InvalidTransmitFrame);
        };
        if frame.owner != self.owner
            || metadata.state != FrameState::AppTx
            || metadata.generation != frame.generation
            || metadata.seen_epoch == epoch
        {
            return Err(AfxdpError::InvalidTransmitFrame);
        }
        metadata.seen_epoch = epoch;
        validate_ipv4_length(packet.len(), self.maximum_ipv4_packet)?;
        let payload_offset = self.umem.frame_base(index) + self.umem.headroom + ETHERNET_HEADER_LEN;
        let ipv4 = self.umem.bytes(payload_offset, packet.len());
        validate_complete_ipv4(ipv4)?;
        Ok(())
    }

    fn prepare_tx_descriptor(
        &mut self,
        frame: AfxdpTxFrame,
        ipv4_length: usize,
    ) -> Result<libc::xdp_desc, AfxdpError> {
        let index = frame.index as usize;
        let frame_base = self.umem.frame_base(index);
        let ethernet_offset = frame_base + self.umem.headroom;
        let header: &mut [u8; ETHERNET_HEADER_LEN] = self
            .umem
            .bytes_mut(ethernet_offset, ETHERNET_HEADER_LEN)
            .try_into()
            .map_err(|_| AfxdpError::InvalidKernelLayout)?;
        write_ipv4_header(header, self.config.ethernet_path);
        Ok(libc::xdp_desc {
            addr: ethernet_offset as u64,
            len: (ETHERNET_HEADER_LEN + ipv4_length) as u32,
            options: 0,
        })
    }

    fn wake_rx_if_needed(&mut self) {
        if !self.fill_ring.needs_wakeup() {
            return;
        }
        let mut pollfd = libc::pollfd {
            fd: self.descriptor.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            // safety: pollfd points to one initialized entry for the duration of poll.
            let result = unsafe { libc::poll(&raw mut pollfd, 1, 0) };
            if result >= 0 {
                if pollfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                    self.statistics.rx_wakeup_errors =
                        self.statistics.rx_wakeup_errors.saturating_add(1);
                    self.fatal_error
                        .get_or_insert(FatalError::System(libc::EIO));
                }
                return;
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            self.statistics.rx_wakeup_errors = self.statistics.rx_wakeup_errors.saturating_add(1);
            self.fatal_error.get_or_insert(FatalError::System(
                error.raw_os_error().unwrap_or(libc::EIO),
            ));
            return;
        }
    }

    fn wake_tx_if_needed(&mut self) {
        if !self.tx_ring.needs_wakeup() {
            return;
        }
        loop {
            // safety: zero-length sendto uses no data or address pointers and only kicks this socket.
            let result = unsafe {
                libc::sendto(
                    self.descriptor.as_raw_fd(),
                    ptr::null(),
                    0,
                    libc::MSG_DONTWAIT,
                    ptr::null(),
                    0,
                )
            };
            if result >= 0 {
                return;
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            self.statistics.tx_wakeup_errors = self.statistics.tx_wakeup_errors.saturating_add(1);
            let errno = error.raw_os_error().unwrap_or(libc::EIO);
            if !matches!(errno, libc::EAGAIN | libc::ENOBUFS | libc::EBUSY) {
                self.fatal_error.get_or_insert(FatalError::System(errno));
            }
            return;
        }
    }
}

impl PacketIo for AfxdpSocket {
    type Error = AfxdpError;

    fn max_ipv4_packet(&self) -> usize {
        self.maximum_ipv4_packet
    }

    fn transmit_ipv4(&mut self, packet: &[u8]) -> Result<(), Self::Error> {
        validate_ipv4_length(packet.len(), self.maximum_ipv4_packet)?;
        validate_complete_ipv4(packet)?;
        self.reap_tx_completions(self.config.completion_ring_size as usize)?;

        let mut frames = [None];
        if self.acquire_tx_batch(&mut frames)? == 0 {
            return Err(AfxdpError::WouldBlock);
        }
        let frame = frames[0].take().ok_or(AfxdpError::InvalidTransmitFrame)?;
        match self.tx_ipv4_buffer(&frame) {
            Ok(output) => output[..packet.len()].copy_from_slice(packet),
            Err(error) => {
                let mut release = [Some(frame)];
                let _ = self.release_tx_batch(&mut release);
                return Err(error);
            }
        }

        let mut packets = [TxPacket::new(frame, packet.len())];
        match self.submit_tx_batch(&mut packets) {
            Ok(1) => Ok(()),
            Ok(0) => {
                let mut release = [packets[0].take_frame()];
                self.release_tx_batch(&mut release)?;
                Err(AfxdpError::WouldBlock)
            }
            Ok(_) => Err(AfxdpError::CorruptRing),
            Err(error) => {
                if error.submitted() == 0 {
                    let mut release = [packets[0].take_frame()];
                    self.release_tx_batch(&mut release)?;
                    Err(error.into_error())
                } else {
                    Ok(())
                }
            }
        }
    }

    fn receive_ipv4(&mut self, output: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        let mut frames = [None];
        if self.receive_batch(&mut frames)? == 0 {
            return Ok(None);
        }
        let frame = frames[0].take().ok_or(AfxdpError::InvalidReceiveFrame)?;
        let packet = match self.rx_ipv4(&frame) {
            Ok(packet) => packet,
            Err(error) => {
                let mut recycle = [Some(frame)];
                let _ = self.recycle_rx_batch(&mut recycle);
                return Err(error);
            }
        };
        if output.len() < packet.len() {
            let required = packet.len();
            let mut recycle = [Some(frame)];
            self.recycle_rx_batch(&mut recycle)?;
            return Err(AfxdpError::OutputTooSmall {
                required,
                available: output.len(),
            });
        }
        let length = packet.len();
        output[..length].copy_from_slice(packet);
        let mut recycle = [Some(frame)];
        self.recycle_rx_batch(&mut recycle)?;
        Ok(Some(length))
    }
}

impl PacketBatchIo for AfxdpSocket {
    type RxFrame = AfxdpRxFrame;
    type TxFrame = AfxdpTxFrame;

    fn receive_batch(
        &mut self,
        frames: &mut [Option<Self::RxFrame>],
    ) -> Result<usize, Self::Error> {
        if frames.iter().any(Option::is_some) {
            return Err(AfxdpError::OutputSlotOccupied);
        }
        self.check_health()?;
        self.wake_rx_if_needed();
        self.check_health()?;
        let requested = usize_to_u32_saturating(frames.len());
        let (start, count) = self.rx_ring.peek(requested)?;
        let mut output_count = 0;
        let mut refilled = false;
        for offset in 0..count {
            let descriptor = self.rx_ring.read(start.wrapping_add(offset));
            let (frame, descriptor_refilled) = self.receive_descriptor(descriptor);
            refilled |= descriptor_refilled;
            if let Some(frame) = frame {
                frames[output_count] = Some(frame);
                output_count += 1;
            }
        }
        self.rx_ring.release(start, count);
        if refilled {
            self.wake_rx_if_needed();
        }
        Ok(output_count)
    }

    fn rx_ipv4<'a>(&'a self, frame: &Self::RxFrame) -> Result<&'a [u8], Self::Error> {
        let index = self
            .valid_rx_frame(*frame)
            .ok_or(AfxdpError::InvalidReceiveFrame)?;
        let offset = self.umem.frame_base(index) + frame.ipv4_offset as usize;
        Ok(self.umem.bytes(offset, frame.ipv4_length as usize))
    }

    fn recycle_rx_batch(
        &mut self,
        frames: &mut [Option<Self::RxFrame>],
    ) -> Result<(), Self::Error> {
        let count = self.validate_receive_handles(frames)?;
        if count == 0 {
            return Ok(());
        }
        let requested = u32::try_from(count).map_err(|_| AfxdpError::CorruptRing)?;
        let (start, available) = self.fill_ring.reserve(requested)?;
        if available != requested {
            return Err(AfxdpError::CorruptRing);
        }

        let mut ring_offset = 0_u32;
        for slot in frames {
            let Some(frame) = slot.take() else {
                continue;
            };
            let index = frame.index as usize;
            self.frames[index].generation += 1;
            self.frames[index].state = FrameState::FillRing;
            self.fill_ring.write(
                start.wrapping_add(ring_offset),
                self.umem.frame_address(index),
            );
            ring_offset = ring_offset.wrapping_add(1);
        }
        self.fill_ring.submit(start, requested);
        self.wake_rx_if_needed();
        Ok(())
    }

    fn acquire_tx_batch(
        &mut self,
        frames: &mut [Option<Self::TxFrame>],
    ) -> Result<usize, Self::Error> {
        self.check_health()?;
        if frames.iter().any(Option::is_some) {
            return Err(AfxdpError::OutputSlotOccupied);
        }
        let count = frames.len().min(self.tx_free.len());
        for index in self.tx_free.iter().rev().take(count) {
            let Some(metadata) = self.frames.get(*index as usize) else {
                return Err(AfxdpError::CorruptRing);
            };
            if metadata.state != FrameState::FreeTx {
                return Err(AfxdpError::CorruptRing);
            }
        }
        let mut acquired = 0;
        for slot in &mut frames[..count] {
            let Some(index) = self.tx_free.pop() else {
                break;
            };
            let metadata = &mut self.frames[index as usize];
            metadata.state = FrameState::AppTx;
            *slot = Some(AfxdpTxFrame {
                owner: self.owner,
                index,
                generation: metadata.generation,
            });
            acquired += 1;
        }
        Ok(acquired)
    }

    fn tx_ipv4_buffer<'a>(
        &'a mut self,
        frame: &Self::TxFrame,
    ) -> Result<&'a mut [u8], Self::Error> {
        let index = self
            .valid_tx_frame(*frame)
            .ok_or(AfxdpError::InvalidTransmitFrame)?;
        let offset = self.umem.frame_base(index) + self.umem.headroom + ETHERNET_HEADER_LEN;
        Ok(self.umem.bytes_mut(offset, self.maximum_ipv4_packet))
    }

    fn submit_tx_batch(
        &mut self,
        packets: &mut [TxPacket<Self::TxFrame>],
    ) -> Result<usize, SubmitError<Self::Error>> {
        self.check_health()
            .map_err(|error| SubmitError::new(0, error))?;
        let requested = usize_to_u32_saturating(packets.len());
        let (start, capacity) = self
            .tx_ring
            .reserve(requested)
            .map_err(|error| SubmitError::new(0, error))?;
        if capacity == 0 {
            return Ok(0);
        }

        let epoch = self.next_validation_epoch();
        let mut valid = 0_u32;
        let mut validation_error = None;
        for packet in packets.iter().take(capacity as usize) {
            match self.validate_tx_packet(packet, epoch) {
                Ok(()) => valid = valid.wrapping_add(1),
                Err(error) => {
                    validation_error = Some(error);
                    break;
                }
            }
        }

        for offset in 0..valid {
            let packet = &packets[offset as usize];
            let Some(frame) = packet.frame().copied() else {
                return Err(SubmitError::new(0, AfxdpError::MissingTransmitFrame));
            };
            let descriptor = self
                .prepare_tx_descriptor(frame, packet.len())
                .map_err(|error| SubmitError::new(0, error))?;
            self.tx_ring.write(start.wrapping_add(offset), descriptor);
        }

        let mut transferred = 0_u32;
        for packet in packets.iter_mut().take(valid as usize) {
            let Some(frame) = packet.take_frame() else {
                self.tx_ring.submit(start, transferred);
                self.wake_tx_if_needed();
                return Err(SubmitError::new(
                    transferred as usize,
                    AfxdpError::MissingTransmitFrame,
                ));
            };
            self.frames[frame.index as usize].state = FrameState::TxRing;
            transferred = transferred.wrapping_add(1);
        }
        self.tx_ring.submit(start, transferred);
        self.wake_tx_if_needed();

        if let Some(error) = validation_error {
            Err(SubmitError::new(transferred as usize, error))
        } else {
            Ok(transferred as usize)
        }
    }

    fn release_tx_batch(
        &mut self,
        frames: &mut [Option<Self::TxFrame>],
    ) -> Result<(), Self::Error> {
        let count = self.validate_transmit_handles(frames)?;
        if count > self.tx_free.capacity() - self.tx_free.len() {
            return Err(AfxdpError::CorruptRing);
        }
        for slot in frames {
            let Some(frame) = slot.take() else {
                continue;
            };
            let index = frame.index as usize;
            self.frames[index].generation += 1;
            self.frames[index].state = FrameState::FreeTx;
            self.tx_free.push(frame.index);
        }
        Ok(())
    }

    fn reap_tx_completions(&mut self, budget: usize) -> Result<usize, Self::Error> {
        self.check_health()?;
        let requested = usize_to_u32_saturating(budget);
        let (start, count) = self.completion_ring.peek(requested)?;
        let mut reclaimed = 0;
        for offset in 0..count {
            let address = self.completion_ring.read(start.wrapping_add(offset));
            let valid = self
                .umem
                .frame_index_for_range(address, 1)
                .filter(|&(index, offset)| {
                    index >= self.rx_frame_count
                        && offset == self.umem.headroom
                        && self.frames[index].state == FrameState::TxRing
                });
            let Some((index, _)) = valid else {
                self.statistics.invalid_completions =
                    self.statistics.invalid_completions.saturating_add(1);
                self.fatal_error.get_or_insert(FatalError::Completion);
                continue;
            };
            if self.tx_free.len() == self.tx_free.capacity() {
                self.fatal_error.get_or_insert(FatalError::Completion);
                continue;
            }
            let Some(generation) = self.frames[index].generation.checked_add(1) else {
                self.retire_frame(index);
                continue;
            };
            self.frames[index].generation = generation;
            self.frames[index].state = FrameState::FreeTx;
            self.tx_free.push(index as u32);
            reclaimed += 1;
        }
        self.completion_ring.release(start, count);
        self.statistics.reclaimed_tx_frames = self
            .statistics
            .reclaimed_tx_frames
            .saturating_add(reclaimed as u64);
        // A prior EAGAIN/ENOBUFS kick must not leave published descriptors stranded.
        self.wake_tx_if_needed();
        self.check_health()?;
        Ok(reclaimed)
    }
}

#[derive(Clone, Copy, Debug)]
struct ValidatedConfig {
    frame_count: usize,
    tx_frame_count: usize,
    rx_frame_count: usize,
    maximum_ipv4_packet: usize,
}

impl ValidatedConfig {
    fn new(config: AfxdpConfig) -> Result<Self, AfxdpError> {
        if config.interface_index == 0 {
            return Err(AfxdpError::InvalidConfig("interface index must be nonzero"));
        }
        if !matches!(config.frame_size, UMEM_FRAME_2K | UMEM_FRAME_4K) {
            return Err(AfxdpError::InvalidConfig(
                "aligned UMEM frame size must be 2048 or 4096 bytes",
            ));
        }
        if config.frame_count < 2 {
            return Err(AfxdpError::InvalidConfig(
                "UMEM requires at least two frames",
            ));
        }
        if config.tx_frame_count == 0 || config.tx_frame_count >= config.frame_count {
            return Err(AfxdpError::InvalidConfig(
                "TX frame count must leave at least one RX frame",
            ));
        }
        for (size, name) in [
            (config.rx_ring_size, "RX ring"),
            (config.tx_ring_size, "TX ring"),
            (config.fill_ring_size, "fill ring"),
            (config.completion_ring_size, "completion ring"),
        ] {
            if size == 0 || !size.is_power_of_two() {
                return Err(AfxdpError::InvalidConfig(match name {
                    "RX ring" => "RX ring size must be a nonzero power of two",
                    "TX ring" => "TX ring size must be a nonzero power of two",
                    "fill ring" => "fill ring size must be a nonzero power of two",
                    _ => "completion ring size must be a nonzero power of two",
                }));
            }
        }

        let frame_count = config.frame_count as usize;
        let tx_frame_count = config.tx_frame_count as usize;
        let rx_frame_count = frame_count - tx_frame_count;
        if config.fill_ring_size < rx_frame_count as u32 {
            return Err(AfxdpError::InvalidConfig(
                "fill ring must hold every RX-owned UMEM frame",
            ));
        }
        if config.completion_ring_size < config.tx_frame_count {
            return Err(AfxdpError::InvalidConfig(
                "completion ring must hold every TX-owned UMEM frame",
            ));
        }

        let frame_size = config.frame_size as usize;
        let headroom = config.headroom as usize;
        let overhead = headroom
            .checked_add(ETHERNET_HEADER_LEN)
            .ok_or(AfxdpError::InvalidConfig("headroom overflows usize"))?;
        let maximum_ipv4_packet =
            frame_size
                .checked_sub(overhead)
                .ok_or(AfxdpError::InvalidConfig(
                    "headroom leaves no packet storage",
                ))?;
        if maximum_ipv4_packet < rocev2_wire::IPV4_HEADER_LEN {
            return Err(AfxdpError::InvalidConfig(
                "headroom leaves less than one IPv4 header",
            ));
        }

        frame_size
            .checked_mul(frame_count)
            .ok_or(AfxdpError::InvalidConfig("UMEM length overflows usize"))?;
        Ok(Self {
            frame_count,
            tx_frame_count,
            rx_frame_count,
            maximum_ipv4_packet,
        })
    }
}

fn validate_ipv4_length(length: usize, maximum: usize) -> Result<(), AfxdpError> {
    if length > maximum {
        return Err(AfxdpError::PacketTooLarge { length, maximum });
    }
    if length < rocev2_wire::IPV4_HEADER_LEN {
        return Err(AfxdpError::InvalidIpv4Packet);
    }
    Ok(())
}

fn validate_complete_ipv4(packet: &[u8]) -> Result<(), AfxdpError> {
    if packet.len() < rocev2_wire::IPV4_HEADER_LEN || packet[0] >> 4 != 4 {
        return Err(AfxdpError::InvalidIpv4Packet);
    }
    let header_length = usize::from(packet[0] & 0x0f) * 4;
    if header_length < rocev2_wire::IPV4_HEADER_LEN || header_length > packet.len() {
        return Err(AfxdpError::InvalidIpv4Packet);
    }
    let total_length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_length != packet.len() {
        return Err(AfxdpError::InvalidIpv4Packet);
    }
    Ok(())
}

fn create_xdp_socket() -> Result<OwnedFd, AfxdpError> {
    // safety: socket has no pointer arguments and a successful fd is owned exactly once below.
    let raw_descriptor = unsafe {
        libc::socket(
            libc::AF_XDP,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if raw_descriptor < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // safety: raw_descriptor is a newly owned, open socket descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(raw_descriptor) })
}

fn register_umem(descriptor: i32, umem: &Umem) -> Result<(), AfxdpError> {
    let registration = umem.registration();
    match set_xdp_option(descriptor, libc::XDP_UMEM_REG, &registration) {
        Ok(()) => Ok(()),
        Err(error) if error.raw_os_error() == Some(libc::EINVAL) => {
            let registration = libc::xdp_umem_reg_v1 {
                addr: registration.addr,
                len: registration.len,
                chunk_size: registration.chunk_size,
                headroom: registration.headroom,
            };
            set_xdp_option(descriptor, libc::XDP_UMEM_REG, &registration)?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn configure_ring(descriptor: i32, option: i32, entries: u32) -> Result<(), AfxdpError> {
    set_xdp_option(descriptor, option, &entries)?;
    Ok(())
}

fn set_xdp_option<T>(descriptor: i32, option: i32, value: &T) -> io::Result<()> {
    let length = libc::socklen_t::try_from(size_of::<T>())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "sockopt size overflow"))?;
    // safety: value points to a live T for exactly length bytes and fd is a live AF_XDP socket.
    let result = unsafe {
        libc::setsockopt(
            descriptor,
            libc::SOL_XDP,
            option,
            ptr::from_ref(value).cast(),
            length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn mmap_offsets(descriptor: i32) -> Result<libc::xdp_mmap_offsets, AfxdpError> {
    let mut offsets = MaybeUninit::<libc::xdp_mmap_offsets>::zeroed();
    let mut length = libc::socklen_t::try_from(size_of::<libc::xdp_mmap_offsets>())
        .map_err(|_| AfxdpError::InvalidKernelLayout)?;
    // safety: offsets provides writable storage for length bytes and length is initialized.
    let result = unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_XDP,
            libc::XDP_MMAP_OFFSETS,
            offsets.as_mut_ptr().cast(),
            &raw mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error().into());
    }
    if length as usize != size_of::<libc::xdp_mmap_offsets>() {
        return Err(AfxdpError::InvalidKernelLayout);
    }
    // safety: getsockopt filled the complete current xdp_mmap_offsets layout.
    Ok(unsafe { offsets.assume_init() })
}

fn socket_zero_copy(descriptor: i32) -> Result<bool, AfxdpError> {
    let mut options = MaybeUninit::<libc::xdp_options>::zeroed();
    let mut length = libc::socklen_t::try_from(size_of::<libc::xdp_options>())
        .map_err(|_| AfxdpError::InvalidKernelLayout)?;
    // safety: options provides writable storage for length bytes and length is initialized.
    let result = unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_XDP,
            libc::XDP_OPTIONS,
            options.as_mut_ptr().cast(),
            &raw mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error().into());
    }
    if length as usize != size_of::<libc::xdp_options>() {
        return Err(AfxdpError::InvalidKernelLayout);
    }
    // safety: getsockopt filled the complete xdp_options layout.
    let options = unsafe { options.assume_init() };
    Ok(options.flags & libc::XDP_OPTIONS_ZEROCOPY != 0)
}

fn xdp_kernel_statistics(descriptor: i32) -> Result<libc::xdp_statistics, AfxdpError> {
    let mut statistics = MaybeUninit::<libc::xdp_statistics>::zeroed();
    let mut length = libc::socklen_t::try_from(size_of::<libc::xdp_statistics>())
        .map_err(|_| AfxdpError::InvalidKernelLayout)?;
    // safety: statistics provides writable storage for length bytes and length is initialized.
    let result = unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_XDP,
            libc::XDP_STATISTICS,
            statistics.as_mut_ptr().cast(),
            &raw mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error().into());
    }
    if (length as usize) < size_of::<libc::xdp_statistics_v1>() {
        return Err(AfxdpError::InvalidKernelLayout);
    }
    // safety: zero-initialization covers fields omitted by older compatible kernels.
    Ok(unsafe { statistics.assume_init() })
}

fn system_page_size() -> Result<usize, AfxdpError> {
    // safety: sysconf has no pointer arguments for _SC_PAGESIZE.
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if value <= 0 {
        return Err(io::Error::last_os_error().into());
    }
    usize::try_from(value).map_err(|_| AfxdpError::InvalidKernelLayout)
}

fn ring_mapping_length<T>(
    offsets: &libc::xdp_ring_offset,
    entries: u32,
) -> Result<usize, AfxdpError> {
    if entries == 0 || !entries.is_power_of_two() {
        return Err(AfxdpError::InvalidConfig(
            "AF_XDP ring size must be a nonzero power of two",
        ));
    }
    let producer_end = checked_mapping_end::<AtomicU32>(offsets.producer, 1)?;
    let consumer_end = checked_mapping_end::<AtomicU32>(offsets.consumer, 1)?;
    let flags_end = checked_mapping_end::<AtomicU32>(offsets.flags, 1)?;
    let descriptor_end = checked_mapping_end::<T>(offsets.desc, entries as usize)?;
    let spans = [
        (offsets.producer as usize, producer_end),
        (offsets.consumer as usize, consumer_end),
        (offsets.flags as usize, flags_end),
        (offsets.desc as usize, descriptor_end),
    ];
    for (index, &(start, end)) in spans.iter().enumerate() {
        for &(other_start, other_end) in &spans[index + 1..] {
            if start < other_end && other_start < end {
                return Err(AfxdpError::InvalidKernelLayout);
            }
        }
    }
    Ok(producer_end
        .max(consumer_end)
        .max(flags_end)
        .max(descriptor_end))
}

fn checked_mapping_end<T>(offset: u64, count: usize) -> Result<usize, AfxdpError> {
    let offset = usize::try_from(offset).map_err(|_| AfxdpError::InvalidKernelLayout)?;
    let bytes = size_of::<T>()
        .checked_mul(count)
        .ok_or(AfxdpError::InvalidKernelLayout)?;
    offset
        .checked_add(bytes)
        .ok_or(AfxdpError::InvalidKernelLayout)
}

fn mapped_pointer<T>(mapping: &Mapping, offset: u64) -> Result<NonNull<T>, AfxdpError> {
    let offset = usize::try_from(offset).map_err(|_| AfxdpError::InvalidKernelLayout)?;
    let end = offset
        .checked_add(size_of::<T>())
        .ok_or(AfxdpError::InvalidKernelLayout)?;
    if end > mapping.length() || offset % align_of::<T>() != 0 {
        return Err(AfxdpError::InvalidKernelLayout);
    }
    // safety: validated offset and alignment keep the pointer inside this live mapping.
    let pointer = unsafe { mapping.pointer().as_ptr().add(offset).cast::<T>() };
    NonNull::new(pointer).ok_or(AfxdpError::InvalidKernelLayout)
}

fn usize_to_u32_saturating(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> AfxdpConfig {
        AfxdpConfig::new(1, 0, EthernetPath::new([1; 6], [2; 6]))
    }

    #[test]
    fn default_config_partitions_umem_without_overlap() {
        let config = ValidatedConfig::new(test_config()).unwrap();
        assert_eq!(config.frame_count, 4096);
        assert_eq!(config.rx_frame_count, 3072);
        assert_eq!(config.tx_frame_count, 1024);
        assert_eq!(config.maximum_ipv4_packet, 4096 - ETHERNET_HEADER_LEN);
    }

    #[test]
    fn rejects_non_power_of_two_ring() {
        let mut config = test_config();
        config.rx_ring_size = 1000;
        assert!(matches!(
            ValidatedConfig::new(config),
            Err(AfxdpError::InvalidConfig(_))
        ));
    }

    #[test]
    fn rejects_fill_ring_smaller_than_rx_pool() {
        let mut config = test_config();
        config.fill_ring_size = 2048;
        assert!(matches!(
            ValidatedConfig::new(config),
            Err(AfxdpError::InvalidConfig(_))
        ));
    }

    #[test]
    fn validates_complete_ipv4_length() {
        let mut packet = [0_u8; rocev2_wire::IPV4_HEADER_LEN];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(rocev2_wire::IPV4_HEADER_LEN as u16).to_be_bytes());
        assert!(validate_complete_ipv4(&packet).is_ok());
        packet[3] = 19;
        assert!(matches!(
            validate_complete_ipv4(&packet),
            Err(AfxdpError::InvalidIpv4Packet)
        ));
    }

    #[test]
    fn ring_mapping_length_checks_every_shared_field() {
        let offsets = libc::xdp_ring_offset {
            producer: 0,
            consumer: 64,
            desc: 128,
            flags: 4,
        };
        let length = ring_mapping_length::<libc::xdp_desc>(&offsets, 64).unwrap();
        assert_eq!(length, 128 + 64 * size_of::<libc::xdp_desc>());
    }

    fn test_ring<T>(size: u32) -> RingMemory<T> {
        let offsets = libc::xdp_ring_offset {
            producer: 0,
            consumer: 64,
            flags: 128,
            desc: 192,
        };
        let mapping = Mapping::anonymous(
            ring_mapping_length::<T>(&offsets, size).unwrap(),
            UmemBacking::Regular,
        )
        .unwrap();
        RingMemory {
            producer: mapped_pointer(&mapping, offsets.producer).unwrap(),
            consumer: mapped_pointer(&mapping, offsets.consumer).unwrap(),
            flags: mapped_pointer(&mapping, offsets.flags).unwrap(),
            descriptors: mapped_pointer(&mapping, offsets.desc).unwrap(),
            _mapping: mapping,
            size,
            mask: size - 1,
        }
    }

    fn simulated_socket() -> AfxdpSocket {
        let mut config = test_config();
        config.frame_count = 8;
        config.tx_frame_count = 4;
        config.headroom = 64;
        config.fill_ring_size = 8;
        config.completion_ring_size = 4;
        let mut tx_free = Vec::with_capacity(4);
        tx_free.extend(4..8);
        AfxdpSocket {
            steering: None,
            owner: NEXT_SOCKET_ID.fetch_add(1, Ordering::Relaxed),
            fatal_error: None,
            descriptor: std::fs::File::open("/dev/null").unwrap().into(),
            rx_ring: ConsumerRing {
                memory: test_ring(4),
            },
            tx_ring: ProducerRing {
                memory: test_ring(4),
            },
            fill_ring: ProducerRing {
                memory: test_ring(8),
            },
            completion_ring: ConsumerRing {
                memory: test_ring(4),
            },
            umem: Umem::new(config).unwrap(),
            frames: (0..8)
                .map(|index| FrameMeta {
                    generation: 0,
                    seen_epoch: 0,
                    state: if index < 4 {
                        FrameState::FillRing
                    } else {
                        FrameState::FreeTx
                    },
                })
                .collect(),
            tx_free,
            rx_frame_count: 4,
            maximum_ipv4_packet: 4096 - 64 - ETHERNET_HEADER_LEN,
            config,
            zero_copy: false,
            validation_epoch: 0,
            statistics: AfxdpStatistics::default(),
            _single_owner: PhantomData,
        }
    }

    fn publish_completion(socket: &mut AfxdpSocket, address: u64) {
        let memory = &socket.completion_ring.memory;
        let producer = memory.producer().load(Ordering::Relaxed);
        // safety: this test acts as the kernel producer of its private simulated ring.
        unsafe {
            ptr::write_volatile(memory.descriptor_pointer(producer), address);
        }
        memory
            .producer()
            .store(producer.wrapping_add(1), Ordering::Release);
    }

    fn submit_test_packet(socket: &mut AfxdpSocket) -> AfxdpTxFrame {
        let mut frames = [None];
        assert_eq!(socket.acquire_tx_batch(&mut frames).unwrap(), 1);
        let handle = frames[0].take().unwrap();
        let packet = socket.tx_ipv4_buffer(&handle).unwrap();
        packet[..20].fill(0);
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20_u16.to_be_bytes());
        let mut packets = [TxPacket::new(handle, 20)];
        assert_eq!(socket.submit_tx_batch(&mut packets).unwrap(), 1);
        assert!(packets[0].frame().is_none());
        handle
    }

    #[test]
    fn handles_cannot_cross_socket_ownership() {
        let mut first = simulated_socket();
        let mut second = simulated_socket();
        let mut a = [None];
        let mut b = [None];
        first.acquire_tx_batch(&mut a).unwrap();
        second.acquire_tx_batch(&mut b).unwrap();
        assert_eq!(a[0].unwrap().index, b[0].unwrap().index);
        assert!(second.tx_ipv4_buffer(&a[0].unwrap()).is_err());
        assert!(second.release_tx_batch(&mut a).is_err());
        assert!(a[0].is_some());
        first.release_tx_batch(&mut a).unwrap();
        second.release_tx_batch(&mut b).unwrap();
    }

    #[test]
    fn completion_reclaims_only_the_exact_outstanding_address() {
        let mut socket = simulated_socket();
        let handle = submit_test_packet(&mut socket);
        assert_eq!(socket.tx_free.len(), 3);
        assert!(socket.tx_ipv4_buffer(&handle).is_err());
        let address = socket.umem.frame_address(handle.index as usize) + 64;
        publish_completion(&mut socket, address);
        assert_eq!(socket.reap_tx_completions(4).unwrap(), 1);
        assert_eq!(socket.tx_free.len(), 4);
        assert_eq!(socket.statistics().reclaimed_tx_frames, 1);
        assert!(socket.tx_ipv4_buffer(&handle).is_err());
        publish_completion(&mut socket, address);
        assert!(matches!(
            socket.reap_tx_completions(4),
            Err(AfxdpError::CorruptCompletion)
        ));
        assert_eq!(socket.tx_free.len(), 4);
        assert_eq!(socket.statistics().invalid_completions, 1);
    }

    #[test]
    fn invalid_completion_offsets_never_free_a_live_tx_frame() {
        for offset in [0, 1, 63, 65, 4095] {
            let mut socket = simulated_socket();
            let handle = submit_test_packet(&mut socket);
            publish_completion(&mut socket, u64::from(handle.index) * 4096 + offset);
            assert!(socket.reap_tx_completions(4).is_err());
            assert_eq!(
                socket.frames[handle.index as usize].state,
                FrameState::TxRing
            );
            assert_eq!(socket.tx_free.len(), 3);
        }
    }

    #[test]
    fn generation_exhaustion_retires_instead_of_revalidating_stale_handles() {
        let mut socket = simulated_socket();
        let handle = submit_test_packet(&mut socket);
        socket.frames[handle.index as usize].generation = u64::MAX;
        let address = socket.umem.frame_address(handle.index as usize) + 64;
        publish_completion(&mut socket, address);
        assert!(matches!(
            socket.reap_tx_completions(4),
            Err(AfxdpError::IdentityExhausted)
        ));
        assert_eq!(socket.statistics().retired_frames, 1);
        assert_eq!(socket.tx_free.len(), 3);
    }

    #[test]
    fn ring_wraparound_preserves_capacity_and_publication_order() {
        let mut ring = ProducerRing::<u64> {
            memory: test_ring(4),
        };
        ring.memory
            .producer()
            .store(u32::MAX - 1, Ordering::Relaxed);
        ring.memory
            .consumer()
            .store(u32::MAX - 1, Ordering::Relaxed);
        let (start, count) = ring.reserve(9).unwrap();
        assert_eq!(count, 4);
        for index in 0..count {
            ring.write(start.wrapping_add(index), u64::from(index));
        }
        ring.submit(start, count);
        assert_eq!(ring.memory.producer().load(Ordering::Acquire), 2);
        assert_eq!(ring.reserve(1).unwrap().1, 0);
        ring.memory.consumer().store(2, Ordering::Release);
        assert_eq!(ring.reserve(4).unwrap().1, 4);
    }

    #[test]
    fn overlapping_kernel_ring_fields_are_rejected() {
        let offsets = libc::xdp_ring_offset {
            producer: 0,
            consumer: 0,
            flags: 4,
            desc: 128,
        };
        assert!(matches!(
            ring_mapping_length::<u64>(&offsets, 4),
            Err(AfxdpError::InvalidKernelLayout)
        ));
    }
}
