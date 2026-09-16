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

#[allow(unsafe_code)]
mod raw;

const SLOT_BITS: u32 = 12;
const SLOT_MASK: u32 = (1 << SLOT_BITS) - 1;
const MAX_REGIONS: usize = 1 << SLOT_BITS;
const LOCAL_KEY_DOMAIN: u32 = 0x4c4b_4559;
const REMOTE_KEY_DOMAIN: u32 = 0x524b_4559;

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

    const KNOWN_BITS: u8 =
        Self::LOCAL_WRITE.0 | Self::REMOTE_WRITE.0 | Self::REMOTE_READ.0;

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
            Self::EmptyRegion => "zero-length memory region",
            Self::RemoteWriteRequiresLocalWrite => {
                "remote write requires local write permission"
            }
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
    _exclusive: PhantomData<&'a mut [u8]>,
}

/// Fixed-capacity registered-memory table.
///
/// The low 12 key bits encode a table slot for constant-time lookup; the upper
/// 20 bits are a seed- and generation-dependent tag. The exact key is always
/// checked against the live slot, so malformed and stale keys fail before any
/// pointer arithmetic occurs.
pub struct MemoryRegistry<'a, const N: usize> {
    slots: [Option<Slot<'a>>; N],
    generations: [u32; N],
    seed: u32,
    registered: usize,
}

impl<'a, const N: usize> MemoryRegistry<'a, N> {
    /// Create an empty registry using `seed` to diversify generated keys.
    pub fn new(seed: u32) -> Result<Self, MemoryError> {
        if N > MAX_REGIONS {
            return Err(MemoryError::RegistryTooLarge);
        }

        Ok(Self {
            slots: core::array::from_fn(|_| None),
            generations: [0; N],
            seed,
            registered: 0,
        })
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
        if memory.is_empty() {
            return Err(MemoryError::EmptyRegion);
        }
        if access.contains(AccessFlags::REMOTE_WRITE)
            && !access.contains(AccessFlags::LOCAL_WRITE)
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

        let slot_u32 =
            u32::try_from(slot_index).map_err(|_| MemoryError::RegistryTooLarge)?;
        let slot_u16 =
            u16::try_from(slot_index).map_err(|_| MemoryError::RegistryTooLarge)?;
        let mut generation = self.generations[slot_index];
        let (lkey, rkey) = loop {
            generation = generation.wrapping_add(1).max(1);
            let lkey = make_key(self.seed, generation, slot_u32, LOCAL_KEY_DOMAIN);
            let rkey = make_key(self.seed, generation, slot_u32, REMOTE_KEY_DOMAIN);
            if lkey != 0 && rkey != 0 && lkey != rkey {
                break (lkey, rkey);
            }
        };
        self.generations[slot_index] = generation;

        self.slots[slot_index] = Some(Slot {
            pointer,
            address,
            length: memory.len(),
            access,
            lkey,
            rkey,
            generation,
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

    /// Remove a live registration and return the original exclusive slice.
    pub fn deregister(
        &mut self,
        handle: RegionHandle,
    ) -> Result<&'a mut [u8], MemoryError> {
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

        let slot = self.slots[index].take().ok_or(MemoryError::InvalidHandle)?;
        self.registered -= 1;

        // SAFETY: register accepted a live exclusive slice with lifetime 'a.
        // The slot has been removed, so the registry retains no alias.
        Ok(unsafe { raw::slice_from_raw_parts_mut(slot.pointer, slot.length) })
    }

    /// Copy from a locally registered source after validating its lkey.
    pub fn read_local(
        &mut self,
        lkey: u32,
        address: u64,
        output: &mut [u8],
    ) -> Result<(), MemoryError> {
        let (pointer, offset) =
            self.resolve(lkey, KeyKind::Local, AccessFlags::NONE, address, output.len())?;
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
        let index = usize::try_from(key & SLOT_MASK).map_err(|_| MemoryError::InvalidKey)?;
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
        let region_length =
            u64::try_from(slot.length).map_err(|_| MemoryError::AddressOverflow)?;
        let region_end = slot
            .address
            .checked_add(region_length)
            .ok_or(MemoryError::AddressOverflow)?;

        if address < slot.address || requested_end > region_end {
            return Err(MemoryError::RangeOutOfBounds);
        }

        let offset = usize::try_from(address - slot.address)
            .map_err(|_| MemoryError::AddressOverflow)?;
        Ok((slot.pointer, offset))
    }
}

#[derive(Clone, Copy)]
enum KeyKind {
    Local,
    Remote,
}

fn make_key(seed: u32, generation: u32, slot_u32: u32, domain: u32) -> u32 {
    const TAG_MASK: u32 = 0x000f_ffff;

    let multiplier = (mix32(seed ^ domain ^ 0xa5a5_5a5a) | 1) & TAG_MASK;
    let increment =
        mix32(seed.rotate_left(13) ^ slot_u32.wrapping_mul(0x9e37_79b9) ^ domain)
            & TAG_MASK;
    let tag = (generation & TAG_MASK)
        .wrapping_mul(multiplier)
        .wrapping_add(increment)
        & TAG_MASK;
    (tag << SLOT_BITS) | slot_u32
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
}
