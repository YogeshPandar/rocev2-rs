//! Buffered production keys from the Linux random source.

use rocev2_memory::{KeyGenerator, MemoryError};

/// Buffered Linux key source for production memory registration.
///
/// One 256-byte entropy refill supplies 64 candidate keys. Live collisions are
/// checked by the registry; retired 32-bit keys can recur. Keys are protection
/// tags, not peer authentication. Construction and refill are control-plane work.
pub struct SystemKeyGenerator {
    bytes: [u8; 256],
    offset: usize,
}

impl SystemKeyGenerator {
    /// Read an initial block from Linux's initialized cryptographic RNG.
    pub fn new() -> std::io::Result<Self> {
        let mut bytes = [0; 256];
        rocev2_io::fill_random(&mut bytes)?;
        Ok(Self { bytes, offset: 0 })
    }
}

impl KeyGenerator for SystemKeyGenerator {
    fn next_key(&mut self) -> Result<u32, MemoryError> {
        if self.offset == self.bytes.len() {
            rocev2_io::fill_random(&mut self.bytes)
                .map_err(|_| MemoryError::KeyGenerationFailed)?;
            self.offset = 0;
        }
        let i = self.offset;
        let key = u32::from_ne_bytes([
            self.bytes[i],
            self.bytes[i + 1],
            self.bytes[i + 2],
            self.bytes[i + 3],
        ]);
        self.bytes[i..i + 4].fill(0);
        self.offset += 4;
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refills_without_exposing_candidate_values() {
        let mut generator = SystemKeyGenerator::new().unwrap();
        for _ in 0..129 {
            let _ = generator.next_key().unwrap();
        }
        assert_eq!(generator.offset, 4);
        assert_eq!(&generator.bytes[..4], &[0; 4]);
    }
}
