//! Audited raw-memory boundary.

use core::ptr::{self, NonNull};

/// Reconstitute the exclusive slice transferred into the registry.
///
/// # Safety
///
/// `pointer..pointer+length` must originate from a live exclusive slice with
/// lifetime `'a`, and no alias may remain when this function is called.
pub(crate) unsafe fn slice_from_raw_parts_mut<'a>(
    pointer: NonNull<u8>,
    length: usize,
) -> &'a mut [u8] {
    // SAFETY: guaranteed by the caller contract.
    unsafe { core::slice::from_raw_parts_mut(pointer.as_ptr(), length) }
}

/// Copy from a checked registered range.
///
/// # Safety
///
/// `pointer.add(offset)..+output.len()` must be readable and must not overlap
/// `output`.
pub(crate) unsafe fn copy_from_registered(pointer: NonNull<u8>, offset: usize, output: &mut [u8]) {
    // SAFETY: guaranteed by the caller contract after range validation.
    unsafe {
        ptr::copy_nonoverlapping(
            pointer.as_ptr().add(offset),
            output.as_mut_ptr(),
            output.len(),
        );
    };
}

/// Copy into a checked registered range.
///
/// # Safety
///
/// `pointer.add(offset)..+input.len()` must be writable and must not overlap
/// `input`.
pub(crate) unsafe fn copy_to_registered(pointer: NonNull<u8>, offset: usize, input: &[u8]) {
    // SAFETY: guaranteed by the caller contract after range validation.
    unsafe { ptr::copy_nonoverlapping(input.as_ptr(), pointer.as_ptr().add(offset), input.len()) };
}
