use crate::{RETH_LEN, WireError};

/// RDMA Extended Transport Header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reth {
    /// Remote virtual address.
    pub virtual_address: u64,
    /// Remote key.
    pub remote_key: u32,
    /// Total operation length in bytes.
    pub dma_length: u32,
}

impl Reth {
    /// Decode a RETH.
    pub fn decode(input: &[u8]) -> Result<Self, WireError> {
        if input.len() < RETH_LEN {
            return Err(WireError::BufferTooShort {
                needed: RETH_LEN,
                actual: input.len(),
            });
        }
        Ok(Self {
            virtual_address: u64::from_be_bytes([
                input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7],
            ]),
            remote_key: u32::from_be_bytes([input[8], input[9], input[10], input[11]]),
            dma_length: u32::from_be_bytes([input[12], input[13], input[14], input[15]]),
        })
    }

    /// Encode a RETH.
    pub fn encode(&self, output: &mut [u8]) -> Result<(), WireError> {
        if output.len() < RETH_LEN {
            return Err(WireError::BufferTooShort {
                needed: RETH_LEN,
                actual: output.len(),
            });
        }
        output[0..8].copy_from_slice(&self.virtual_address.to_be_bytes());
        output[8..12].copy_from_slice(&self.remote_key.to_be_bytes());
        output[12..16].copy_from_slice(&self.dma_length.to_be_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reth_roundtrip() {
        let reth = Reth {
            virtual_address: 0x0123_4567_89ab_cdef,
            remote_key: 0xaabb_ccdd,
            dma_length: 0x1020_3040,
        };
        let mut bytes = [0_u8; RETH_LEN];
        reth.encode(&mut bytes).unwrap();
        assert_eq!(Reth::decode(&bytes).unwrap(), reth);
    }
}
