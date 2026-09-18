//! Linux control-plane entropy; never called by packet processing.

use std::io;

/// Fill a control-plane buffer from Linux's initialized random source.
///
/// This can block during early boot until the kernel RNG is initialized. It
/// handles interrupted and partial reads without falling back to weak entropy.
/// Call only during setup or memory registration, not on a packet path.
pub fn fill_random(output: &mut [u8]) -> io::Result<()> {
    for chunk in output.chunks_mut(256) {
        let mut filled = 0;
        while filled < chunk.len() {
            let remaining = &mut chunk[filled..];
            // SAFETY: remaining is exclusively borrowed and writable for len bytes.
            // getrandom writes synchronously, retains no pointer, and needs no alignment.
            let count =
                unsafe { libc::getrandom(remaining.as_mut_ptr().cast(), remaining.len(), 0) };
            if count < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            let count =
                usize::try_from(count).map_err(|_| io::Error::other("invalid entropy length"))?;
            if count == 0 || count > remaining.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "incomplete kernel entropy",
                ));
            }
            filled += count;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_empty_and_multi_chunk_buffers() {
        fill_random(&mut []).unwrap();
        let mut output = [0; 513];
        fill_random(&mut output).unwrap();
        // Do not assert properties that a valid random sequence could violate.
    }
}
