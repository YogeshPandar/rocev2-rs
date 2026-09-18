//! Checked registered-memory table for local and remote RDMA access.
//!
//! The registry owns exclusive borrows of all registered buffers. Every data
//! operation validates key, permission, address, length, and integer overflow
//! before entering the small audited raw-memory module.

#![no_std]

use core::fmt;
use core::marker::PhantomData;
use core::ops::{BitOr, BitOrAssign};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, Ordering};

mod keys;
pub use keys::KeyGenerator;
use keys::{KeyKind, KeyTable};

#[allow(unsafe_code)]
mod raw;

const MAX_REGIONS: usize = 4096;
const KEY_ATTEMPTS: usize = 64;
static NEXT_REGISTRY_ID: AtomicU32 = AtomicU32::new(1);

/// An owned registration reference that prevents deregistration.
///
/// Return this token to [`MemoryRegistry::release`] exactly once. Dropping or
/// forgetting it without release keeps the region busy until registry drop.
/// The token cannot be cloned and is checked against the originating registry.
#[must_use = "release the lease when the operation completes or is flushed"]
#[derive(Debug)]
pub struct RegionLease {
    registry: u32,
    slot: u16,
    generation: u32,
}

/// Access rights granted to a registered memory region.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct AccessFlags(u8);

impl AccessFlags {
    /// No write or remote access rights.
    pub const NONE: Self = Self(0);
    /// Permit local receive and RDMA READ destinations to modify the region.
    pub const LOCAL_WRITE: Self = Self(1 << 0);
    /// Permit a peer to issue RDMA WRITE into the region.
    pub const REMOTE_WRITE: Self = Self(1 << 1);
    /// Permit a peer to issue RDMA READ from the region.
    pub const REMOTE_READ: Self = Self(1 << 2);

    const KNOWN_BITS: u8 = Self::LOCAL_WRITE.0 | Self::REMOTE_WRITE.0 | Self::REMOTE_READ.0;

    /// Construct flags when every bit is recognized.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        if bits & !Self::KNOWN_BITS == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    /// Return the raw bit representation.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Return whether all rights in `required` are present.
    #[must_use]
    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    /// Return whether no rights are set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl BitOr for AccessFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for AccessFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Public metadata identifying one registered memory region.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RegionHandle {
    address: u64,
    length: u64,
    lkey: u32,
    rkey: u32,
    slot: u16,
    generation: u32,
}

impl RegionHandle {
    /// Return the first registered virtual address.
    #[must_use]
    pub const fn address(self) -> u64 {
        self.address
    }

    /// Return the registered byte length.
    #[must_use]
    pub const fn length(self) -> u64 {
        self.length
    }

    /// Return the local protection key.
    #[must_use]
    pub const fn lkey(self) -> u32 {
        self.lkey
    }

    /// Return the remote protection key.
    #[must_use]
    pub const fn rkey(self) -> u32 {
        self.rkey
    }

    /// Return the rights granted to a remote peer as exchangeable metadata.
    #[must_use]
    pub const fn remote_descriptor(self) -> RemoteMemory {
        RemoteMemory {
            address: self.address,
            length: self.length,
            rkey: self.rkey,
        }
    }
}

/// Memory metadata safe to exchange with a connected peer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RemoteMemory {
    /// First remote virtual address.
    pub address: u64,
    /// Registered byte length.
    pub length: u64,
    /// Remote protection key.
    pub rkey: u32,
}

/// Registered-memory failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryError {
    /// The compile-time registry capacity exceeds the key format.
    RegistryTooLarge,
    /// No free registry slot remains.
    RegistryFull,
    /// A posted operation still holds a registration reference.
    RegionBusy,
    /// A reference counter would overflow.
    ReferenceOverflow,
    /// A lease is not a live reference from this registry.
    InvalidLease,
    /// The key source failed to provide a candidate.
    KeyGenerationFailed,
    /// The key source repeatedly returned zero or colliding keys.
    KeyCollisionLimit,
    /// A generation or deterministic key sequence cannot advance without reuse.
    KeySpaceExhausted,
    /// Process-local registry identities have been exhausted.
    RegistryIdentityExhausted,
    /// Zero-length regions are not accepted.
    EmptyRegion,
    /// Remote write was requested without local write permission.
    RemoteWriteRequiresLocalWrite,
    /// A pointer or region end cannot be represented as a 64-bit address.
    AddressOverflow,
    /// A handle does not identify the currently registered generation.
    InvalidHandle,
    /// A local or remote key is unknown or stale.
    InvalidKey,
    /// The key is valid but the required access right was not granted.
    AccessDenied,
    /// The requested address range is outside the registered region.
    RangeOutOfBounds,
}

impl core::error::Error for MemoryError {}

impl fmt::Display for MemoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RegistryTooLarge => "registry capacity exceeds key format",
            Self::RegistryFull => "registered-memory table is full",
            Self::RegionBusy => "memory region is referenced by pending work",
            Self::ReferenceOverflow => "memory reference counter overflow",
            Self::InvalidLease => "invalid memory-region lease",
            Self::KeyGenerationFailed => "memory key source failed",
            Self::KeyCollisionLimit => "memory key collision retry limit reached",
            Self::KeySpaceExhausted => "memory key or generation space exhausted",
            Self::RegistryIdentityExhausted => "memory registry identity space exhausted",
            Self::EmptyRegion => "zero-length memory region",
            Self::RemoteWriteRequiresLocalWrite => "remote write requires local write permission",
            Self::AddressOverflow => "memory address range overflow",
            Self::InvalidHandle => "invalid or stale memory-region handle",
            Self::InvalidKey => "invalid or stale memory key",
            Self::AccessDenied => "memory access denied",
            Self::RangeOutOfBounds => "memory access is outside registered range",
        })
    }
}

struct Slot<'a> {
    pointer: NonNull<u8>,
    address: u64,
    length: usize,
    access: AccessFlags,
    lkey: u32,
    rkey: u32,
    generation: u32,
    references: u32,
    _exclusive: PhantomData<&'a mut [u8]>,
}

/// Checked data access without permission to replace the owning registry.
///
/// Endpoints return this view instead of `&mut MemoryRegistry` so posted leases
/// cannot be bypassed by swapping out the complete registry.
pub struct MemoryAccess<'registry, 'memory, const N: usize> {
    registry: &'registry mut MemoryRegistry<'memory, N>,
}

impl<const N: usize> MemoryAccess<'_, '_, N> {
    /// Copy from a checked local range.
    pub fn read_local(
        &mut self,
        key: u32,
        address: u64,
        output: &mut [u8],
    ) -> Result<(), MemoryError> {
        self.registry.read_local(key, address, output)
    }

    /// Copy into a checked local range.
    pub fn write_local(&mut self, key: u32, address: u64, input: &[u8]) -> Result<(), MemoryError> {
        self.registry.write_local(key, address, input)
    }

    /// Copy from a checked remote-readable range.
    pub fn read_remote(
        &mut self,
        key: u32,
        address: u64,
        output: &mut [u8],
    ) -> Result<(), MemoryError> {
        self.registry.read_remote(key, address, output)
    }

    /// Copy into a checked remote-writable range.
    pub fn write_remote(
        &mut self,
        key: u32,
        address: u64,
        input: &[u8],
    ) -> Result<(), MemoryError> {
        self.registry.write_remote(key, address, input)
    }
}

/// Fixed-capacity registered-memory table.
///
/// Full-width local and remote keys use a fixed hash table with at most 50%
/// occupancy. Exact key, kind, permission, and range checks precede every copy.
/// Construction needs 32-bit atomics only for a process-local lease identity;
/// packet processing is single-owner, allocation-free, and has no atomics.
pub struct MemoryRegistry<'a, const N: usize> {
    slots: [Option<Slot<'a>>; N],
    generations: [u32; N],
    seed: u32,
    sequence: u32,
    identity: u32,
    keys: KeyTable<N>,
    registered: usize,
}

#[allow(unsafe_code)]
impl<'a, const N: usize> MemoryRegistry<'a, N> {
    /// Create a registry with a deterministic development key sequence.
    ///
    /// This seed is not cryptographic entropy. For production registration use
    /// [`Self::register_with_key_generator`] with an externally seeded CSPRNG.
    pub fn new(seed: u32) -> Result<Self, MemoryError> {
        if N > MAX_REGIONS {
            return Err(MemoryError::RegistryTooLarge);
        }

        let identity = NEXT_REGISTRY_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| MemoryError::RegistryIdentityExhausted)?;
        Ok(Self {
            slots: core::array::from_fn(|_| None),
            generations: [0; N],
            seed,
            sequence: 0,
            identity,
            keys: KeyTable::new(),
            registered: 0,
        })
    }

    /// Borrow checked copy operations without exposing registry replacement.
    pub fn access(&mut self) -> MemoryAccess<'_, 'a, N> {
        MemoryAccess { registry: self }
    }

    /// Return the compile-time region capacity.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Return the number of live registrations.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.registered
    }

    /// Return whether no regions are registered.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.registered == 0
    }

    /// Register an exclusive mutable buffer.
    ///
    /// The buffer remains exclusively borrowed until the registry is dropped
    /// or the registration is removed with [`Self::deregister`].
    pub fn register(
        &mut self,
        memory: &'a mut [u8],
        access: AccessFlags,
    ) -> Result<RegionHandle, MemoryError> {
        self.register_inner(memory, access, None)
    }

    /// Register using caller-supplied full-width key candidates.
    ///
    /// Zero, duplicate, and live-colliding keys are rejected. The source must
    /// supply unpredictable keys in production; keys are not authentication.
    /// No OS entropy source or heap allocation is used by this crate.
    pub fn register_with_key_generator(
        &mut self,
        memory: &'a mut [u8],
        access: AccessFlags,
        generator: &mut impl KeyGenerator,
    ) -> Result<RegionHandle, MemoryError> {
        self.register_inner(memory, access, Some(generator))
    }

    fn register_inner(
        &mut self,
        memory: &'a mut [u8],
        access: AccessFlags,
        mut generator: Option<&mut dyn KeyGenerator>,
    ) -> Result<RegionHandle, MemoryError> {
        if memory.is_empty() {
            return Err(MemoryError::EmptyRegion);
        }
        if access.contains(AccessFlags::REMOTE_WRITE) && !access.contains(AccessFlags::LOCAL_WRITE)
        {
            return Err(MemoryError::RemoteWriteRequiresLocalWrite);
        }

        let slot_index = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(MemoryError::RegistryFull)?;
        let pointer = NonNull::new(memory.as_mut_ptr()).ok_or(MemoryError::AddressOverflow)?;
        let address =
            u64::try_from(pointer.as_ptr() as usize).map_err(|_| MemoryError::AddressOverflow)?;
        let length_u64 = u64::try_from(memory.len()).map_err(|_| MemoryError::AddressOverflow)?;
        address
            .checked_add(length_u64)
            .ok_or(MemoryError::AddressOverflow)?;

        let slot_u16 = u16::try_from(slot_index).map_err(|_| MemoryError::RegistryTooLarge)?;
        let generation = self.generations[slot_index]
            .checked_add(1)
            .ok_or(MemoryError::KeySpaceExhausted)?;
        let lkey = self.next_key(&mut generator, 0)?;
        let rkey = self.next_key(&mut generator, lkey)?;
        if !self.keys.insert(lkey, slot_u16, KeyKind::Local) {
            return Err(MemoryError::RegistryFull);
        }
        if !self.keys.insert(rkey, slot_u16, KeyKind::Remote) {
            self.keys.remove(lkey);
            return Err(MemoryError::RegistryFull);
        }
        self.generations[slot_index] = generation;

        self.slots[slot_index] = Some(Slot {
            pointer,
            address,
            length: memory.len(),
            access,
            lkey,
            rkey,
            generation,
            references: 0,
            _exclusive: PhantomData,
        });
        self.registered += 1;

        Ok(RegionHandle {
            address,
            length: length_u64,
            lkey,
            rkey,
            slot: slot_u16,
            generation,
        })
    }

    fn next_key(
        &mut self,
        generator: &mut Option<&mut dyn KeyGenerator>,
        other: u32,
    ) -> Result<u32, MemoryError> {
        for _ in 0..KEY_ATTEMPTS {
            let key = if let Some(source) = generator {
                source.next_key()?
            } else {
                self.sequence = self
                    .sequence
                    .checked_add(1)
                    .ok_or(MemoryError::KeySpaceExhausted)?;
                // A bijection avoids deterministic key reuse before exhaustion.
                mix32(self.sequence.wrapping_add(self.seed))
            };
            if key != 0 && key != other && !self.keys.contains(key) {
                return Ok(key);
            }
        }
        Err(MemoryError::KeyCollisionLimit)
    }

    /// Retain a live local registration until the returned lease is released.
    ///
    /// This checks the key, not the requested access range. Validate permissions
    /// and the complete operation range before accepting application work.
    pub fn retain_local(&mut self, lkey: u32) -> Result<RegionLease, MemoryError> {
        self.retain(lkey, KeyKind::Local)
    }

    /// Retain a live remote registration for a segmented or deferred operation.
    pub fn retain_remote(&mut self, rkey: u32) -> Result<RegionLease, MemoryError> {
        self.retain(rkey, KeyKind::Remote)
    }

    fn retain(&mut self, key: u32, kind: KeyKind) -> Result<RegionLease, MemoryError> {
        let index = self.keys.get(key, kind).ok_or(MemoryError::InvalidKey)?;
        let slot = self.slots[index].as_mut().ok_or(MemoryError::InvalidKey)?;
        slot.references = slot
            .references
            .checked_add(1)
            .ok_or(MemoryError::ReferenceOverflow)?;
        Ok(RegionLease {
            registry: self.identity,
            slot: index as u16,
            generation: slot.generation,
        })
    }

    /// Release one owned registration reference.
    ///
    /// An invalid token is left in `lease` so it can be returned to its owner.
    /// Releasing `None` is a no-op, simplifying completion and flush cleanup.
    pub fn release(&mut self, lease: &mut Option<RegionLease>) -> Result<(), MemoryError> {
        let Some(token) = lease.as_ref() else {
            return Ok(());
        };
        if token.registry != self.identity {
            return Err(MemoryError::InvalidLease);
        }
        let slot = self
            .slots
            .get_mut(usize::from(token.slot))
            .and_then(Option::as_mut)
            .ok_or(MemoryError::InvalidLease)?;
        if slot.generation != token.generation || slot.references == 0 {
            return Err(MemoryError::InvalidLease);
        }
        slot.references -= 1;
        *lease = None;
        Ok(())
    }

    /// Remove an unreferenced registration and return its original slice.
    ///
    /// Returns [`MemoryError::RegionBusy`] while any retained operation exists.
    pub fn deregister(&mut self, handle: RegionHandle) -> Result<&'a mut [u8], MemoryError> {
        let index = usize::from(handle.slot);
        let slot = self
            .slots
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(MemoryError::InvalidHandle)?;

        if slot.generation != handle.generation
            || slot.lkey != handle.lkey
            || slot.rkey != handle.rkey
            || slot.address != handle.address
            || u64::try_from(slot.length).map_err(|_| MemoryError::AddressOverflow)?
                != handle.length
        {
            return Err(MemoryError::InvalidHandle);
        }

        if slot.references != 0 {
            return Err(MemoryError::RegionBusy);
        }
        let slot = self.slots[index].take().ok_or(MemoryError::InvalidHandle)?;
        self.keys.remove(slot.lkey);
        self.keys.remove(slot.rkey);
        self.registered -= 1;

        // SAFETY: register accepted a live exclusive slice with lifetime 'a.
        // The slot has been removed, so the registry retains no alias.
        Ok(unsafe { raw::slice_from_raw_parts_mut(slot.pointer, slot.length) })
    }

    /// Validate a locally readable range without copying data.
    pub fn validate_local_read(
        &self,
        lkey: u32,
        address: u64,
        length: usize,
    ) -> Result<(), MemoryError> {
        self.resolve(lkey, KeyKind::Local, AccessFlags::NONE, address, length)
            .map(|_| ())
    }

    /// Validate a locally writable range without copying data.
    pub fn validate_local_write(
        &self,
        lkey: u32,
        address: u64,
        length: usize,
    ) -> Result<(), MemoryError> {
        self.resolve(
            lkey,
            KeyKind::Local,
            AccessFlags::LOCAL_WRITE,
            address,
            length,
        )
        .map(|_| ())
    }

    /// Validate a remotely readable range without copying data.
    pub fn validate_remote_read(
        &self,
        rkey: u32,
        address: u64,
        length: usize,
    ) -> Result<(), MemoryError> {
        self.resolve(
            rkey,
            KeyKind::Remote,
            AccessFlags::REMOTE_READ,
            address,
            length,
        )
        .map(|_| ())
    }

    /// Validate a remotely writable range without copying data.
    pub fn validate_remote_write(
        &self,
        rkey: u32,
        address: u64,
        length: usize,
    ) -> Result<(), MemoryError> {
        self.resolve(
            rkey,
            KeyKind::Remote,
            AccessFlags::REMOTE_WRITE,
            address,
            length,
        )
        .map(|_| ())
    }

    /// Copy from a locally registered source after validating its lkey.
    pub fn read_local(
        &mut self,
        lkey: u32,
        address: u64,
        output: &mut [u8],
    ) -> Result<(), MemoryError> {
        let (pointer, offset) = self.resolve(
            lkey,
            KeyKind::Local,
            AccessFlags::NONE,
            address,
            output.len(),
        )?;
        // SAFETY: resolve validated key, range, overflow, and the exclusive
        // registry borrow prevents safe aliases to registered memory.
        unsafe { raw::copy_from_registered(pointer, offset, output) };
        Ok(())
    }

    /// Copy into a locally registered destination after validating local-write access.
    pub fn write_local(
        &mut self,
        lkey: u32,
        address: u64,
        input: &[u8],
    ) -> Result<(), MemoryError> {
        let (pointer, offset) = self.resolve(
            lkey,
            KeyKind::Local,
            AccessFlags::LOCAL_WRITE,
            address,
            input.len(),
        )?;
        // SAFETY: resolve validated key, permission, range, and overflow.
        unsafe { raw::copy_to_registered(pointer, offset, input) };
        Ok(())
    }

    /// Copy bytes for an incoming RDMA READ after validating rkey and permission.
    pub fn read_remote(
        &mut self,
        rkey: u32,
        address: u64,
        output: &mut [u8],
    ) -> Result<(), MemoryError> {
        let (pointer, offset) = self.resolve(
            rkey,
            KeyKind::Remote,
            AccessFlags::REMOTE_READ,
            address,
            output.len(),
        )?;
        // SAFETY: resolve validated key, permission, range, and overflow.
        unsafe { raw::copy_from_registered(pointer, offset, output) };
        Ok(())
    }

    /// Apply an incoming RDMA WRITE after validating rkey and permission.
    pub fn write_remote(
        &mut self,
        rkey: u32,
        address: u64,
        input: &[u8],
    ) -> Result<(), MemoryError> {
        let (pointer, offset) = self.resolve(
            rkey,
            KeyKind::Remote,
            AccessFlags::REMOTE_WRITE,
            address,
            input.len(),
        )?;
        // SAFETY: resolve validated key, permission, range, and overflow.
        unsafe { raw::copy_to_registered(pointer, offset, input) };
        Ok(())
    }

    fn resolve(
        &self,
        key: u32,
        kind: KeyKind,
        required: AccessFlags,
        address: u64,
        length: usize,
    ) -> Result<(NonNull<u8>, usize), MemoryError> {
        let index = self.keys.get(key, kind).ok_or(MemoryError::InvalidKey)?;
        let slot = self
            .slots
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(MemoryError::InvalidKey)?;

        let expected = match kind {
            KeyKind::Local => slot.lkey,
            KeyKind::Remote => slot.rkey,
        };
        if key != expected {
            return Err(MemoryError::InvalidKey);
        }
        if !slot.access.contains(required) {
            return Err(MemoryError::AccessDenied);
        }

        let length_u64 = u64::try_from(length).map_err(|_| MemoryError::AddressOverflow)?;
        let requested_end = address
            .checked_add(length_u64)
            .ok_or(MemoryError::AddressOverflow)?;
        let region_length = u64::try_from(slot.length).map_err(|_| MemoryError::AddressOverflow)?;
        let region_end = slot
            .address
            .checked_add(region_length)
            .ok_or(MemoryError::AddressOverflow)?;

        if address < slot.address || requested_end > region_end {
            return Err(MemoryError::RangeOutOfBounds);
        }

        let offset =
            usize::try_from(address - slot.address).map_err(|_| MemoryError::AddressOverflow)?;
        Ok((slot.pointer, offset))
    }
}

fn mix32(mut value: u32) -> u32 {
    value ^= value >> 16;
    value = value.wrapping_mul(0x7feb_352d);
    value ^= value >> 15;
    value = value.wrapping_mul(0x846c_a68b);
    value ^ (value >> 16)
}

#[cfg(test)]
mod tests {
    use super::*;

    const READ_WRITE: AccessFlags = AccessFlags(
        AccessFlags::LOCAL_WRITE.bits()
            | AccessFlags::REMOTE_WRITE.bits()
            | AccessFlags::REMOTE_READ.bits(),
    );

    #[test]
    fn validates_keys_permissions_and_ranges_before_copy() {
        let mut memory = [0_u8; 16];
        {
            let mut registry = MemoryRegistry::<4>::new(0x1234_5678).unwrap();
            let region = registry.register(&mut memory, READ_WRITE).unwrap();

            registry
                .write_remote(region.rkey(), region.address() + 4, &[1, 2, 3])
                .unwrap();
            let mut output = [0_u8; 3];
            registry
                .read_remote(region.rkey(), region.address() + 4, &mut output)
                .unwrap();
            assert_eq!(output, [1, 2, 3]);

            assert_eq!(
                registry.write_remote(region.rkey() ^ 0x1000, region.address(), &[9]),
                Err(MemoryError::InvalidKey)
            );
            assert_eq!(
                registry.write_remote(region.rkey(), region.address() + 16, &[9]),
                Err(MemoryError::RangeOutOfBounds)
            );
            assert_eq!(
                registry.read_remote(region.rkey(), u64::MAX, &mut [0; 2]),
                Err(MemoryError::AddressOverflow)
            );
        }
        assert_eq!(&memory[4..7], &[1, 2, 3]);
    }

    #[test]
    fn remote_write_requires_both_registration_rights() {
        let mut memory = [0_u8; 8];
        let mut registry = MemoryRegistry::<1>::new(7).unwrap();
        assert_eq!(
            registry.register(&mut memory, AccessFlags::REMOTE_WRITE),
            Err(MemoryError::RemoteWriteRequiresLocalWrite)
        );
    }

    #[test]
    fn read_only_region_rejects_writes() {
        let mut memory = [7_u8; 8];
        let mut registry = MemoryRegistry::<1>::new(9).unwrap();
        let region = registry
            .register(&mut memory, AccessFlags::REMOTE_READ)
            .unwrap();

        assert_eq!(
            registry.write_local(region.lkey(), region.address(), &[1]),
            Err(MemoryError::AccessDenied)
        );
        assert_eq!(
            registry.write_remote(region.rkey(), region.address(), &[1]),
            Err(MemoryError::AccessDenied)
        );

        let mut byte = [0_u8; 1];
        registry
            .read_remote(region.rkey(), region.address(), &mut byte)
            .unwrap();
        assert_eq!(byte, [7]);
    }

    #[test]
    fn deregistration_invalidates_keys_and_restores_slice() {
        let mut memory = [0_u8; 4];
        let mut registry = MemoryRegistry::<1>::new(11).unwrap();
        let first = registry.register(&mut memory, READ_WRITE).unwrap();
        let returned = registry.deregister(first).unwrap();
        returned[0] = 5;

        assert_eq!(
            registry.read_local(first.lkey(), first.address(), &mut [0; 1]),
            Err(MemoryError::InvalidKey)
        );
        assert_eq!(returned[0], 5);
    }

    #[test]
    fn validation_checks_full_range_without_touching_memory() {
        let mut memory = [0_u8; 8];
        let registry_access = AccessFlags::LOCAL_WRITE | AccessFlags::REMOTE_READ;
        let mut registry = MemoryRegistry::<1>::new(17).unwrap();
        let region = registry.register(&mut memory, registry_access).unwrap();

        assert_eq!(
            registry.validate_local_write(region.lkey(), region.address(), 8),
            Ok(())
        );
        assert_eq!(
            registry.validate_remote_read(region.rkey(), region.address() + 7, 2),
            Err(MemoryError::RangeOutOfBounds)
        );
        assert_eq!(
            registry.validate_remote_write(region.rkey(), region.address(), 1),
            Err(MemoryError::AccessDenied)
        );
    }

    #[test]
    fn capacity_is_fixed() {
        let mut first = [0_u8; 1];
        let mut second = [0_u8; 1];
        let mut registry = MemoryRegistry::<1>::new(13).unwrap();
        registry.register(&mut first, AccessFlags::NONE).unwrap();
        assert_eq!(
            registry.register(&mut second, AccessFlags::NONE),
            Err(MemoryError::RegistryFull)
        );
    }
    #[test]
    fn leases_block_deregistration_and_reject_other_registries() {
        let mut bytes = [0; 8];
        let mut registry = MemoryRegistry::<1>::new(3).unwrap();
        let mut other = MemoryRegistry::<1>::new(3).unwrap();
        let handle = registry.register(&mut bytes, READ_WRITE).unwrap();
        let mut local = Some(registry.retain_local(handle.lkey()).unwrap());
        let mut remote = Some(registry.retain_remote(handle.rkey()).unwrap());
        assert_eq!(registry.deregister(handle), Err(MemoryError::RegionBusy));
        assert_eq!(other.release(&mut local), Err(MemoryError::InvalidLease));
        assert!(local.is_some());
        registry.release(&mut local).unwrap();
        registry.release(&mut local).unwrap();
        assert_eq!(registry.deregister(handle), Err(MemoryError::RegionBusy));
        registry.release(&mut remote).unwrap();
        let returned = registry.deregister(handle).unwrap();
        let replacement = registry.register(returned, READ_WRITE).unwrap();
        assert_ne!(handle.lkey(), replacement.lkey());
        assert_ne!(handle.rkey(), replacement.rkey());
        assert_eq!(
            registry.retain_local(handle.lkey()).unwrap_err(),
            MemoryError::InvalidKey
        );
        assert_eq!(registry.deregister(handle), Err(MemoryError::InvalidHandle));
    }

    struct Candidates<'a>(&'a [u32]);

    impl KeyGenerator for Candidates<'_> {
        fn next_key(&mut self) -> Result<u32, MemoryError> {
            let (key, remaining) = self
                .0
                .split_first()
                .ok_or(MemoryError::KeyGenerationFailed)?;
            self.0 = remaining;
            Ok(*key)
        }
    }

    #[test]
    fn external_keys_use_all_bits_and_skip_zero_and_live_collisions() {
        let mut first = [0; 1];
        let mut second = [0; 1];
        let mut registry = MemoryRegistry::<2>::new(7).unwrap();
        let mut generator = Candidates(&[0, 1, 1, u32::MAX, 1, u32::MAX, 0xdead_beef, 0xcafe_babe]);
        let a = registry
            .register_with_key_generator(&mut first, READ_WRITE, &mut generator)
            .unwrap();
        let b = registry
            .register_with_key_generator(&mut second, READ_WRITE, &mut generator)
            .unwrap();
        assert_eq!((a.lkey(), a.rkey()), (1, u32::MAX));
        assert_eq!((b.lkey(), b.rkey()), (0xdead_beef, 0xcafe_babe));
        assert_eq!(
            registry.validate_remote_read(a.lkey(), a.address(), 1),
            Err(MemoryError::InvalidKey)
        );
        assert_eq!(
            registry.validate_local_read(a.rkey(), a.address(), 1),
            Err(MemoryError::InvalidKey)
        );
    }

    #[test]
    fn failed_key_source_never_publishes_a_partial_registration() {
        let mut first = [0; 1];
        let mut second = [0; 1];
        let mut registry = MemoryRegistry::<1>::new(7).unwrap();
        let mut generator = Candidates(&[42]);
        assert_eq!(
            registry.register_with_key_generator(&mut first, READ_WRITE, &mut generator),
            Err(MemoryError::KeyGenerationFailed)
        );
        assert!(registry.is_empty());
        assert!(!registry.keys.contains(42));
        registry.register(&mut second, READ_WRITE).unwrap();
    }

    #[test]
    fn exhausted_keys_generations_and_references_do_not_wrap() {
        let mut bytes = [0; 1];
        let mut registry = MemoryRegistry::<1>::new(7).unwrap();
        let handle = registry.register(&mut bytes, READ_WRITE).unwrap();
        registry.slots[0].as_mut().unwrap().references = u32::MAX;
        assert_eq!(
            registry.retain_local(handle.lkey()).unwrap_err(),
            MemoryError::ReferenceOverflow
        );
        registry.slots[0].as_mut().unwrap().references = 0;
        let bytes = registry.deregister(handle).unwrap();
        registry.sequence = u32::MAX;
        assert_eq!(
            registry.register(bytes, READ_WRITE),
            Err(MemoryError::KeySpaceExhausted)
        );
        assert!(registry.is_empty());
    }

    #[test]
    fn repeated_candidate_source_is_bounded() {
        struct Zero;
        impl KeyGenerator for Zero {
            fn next_key(&mut self) -> Result<u32, MemoryError> {
                Ok(0)
            }
        }
        let mut bytes = [0; 1];
        let mut registry = MemoryRegistry::<1>::new(0).unwrap();
        assert_eq!(
            registry.register_with_key_generator(&mut bytes, READ_WRITE, &mut Zero),
            Err(MemoryError::KeyCollisionLimit)
        );
        assert!(registry.is_empty());
    }
}
