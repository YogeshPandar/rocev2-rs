//! Allocation-free operation segmentation.

use rocev2_wire::Opcode;

/// Logical transfer whose payload is split into RC packets.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TransferKind {
    /// SEND request.
    Send,
    /// RDMA WRITE request.
    Write,
    /// RDMA READ response.
    ReadResponse,
}

/// Segmentation setup failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SegmentError {
    /// A zero-byte payload capacity would make forward progress impossible.
    ZeroPayloadCapacity,
}

/// One borrowed payload segment and its corresponding RC opcode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Segment<'a> {
    opcode: Opcode,
    offset: usize,
    payload: &'a [u8],
}

impl<'a> Segment<'a> {
    /// Return the opcode appropriate for this segment position.
    #[must_use]
    pub const fn opcode(self) -> Opcode {
        self.opcode
    }

    /// Return the byte offset in the complete logical transfer.
    #[must_use]
    pub const fn offset(self) -> usize {
        self.offset
    }

    /// Return the borrowed payload bytes.
    #[must_use]
    pub const fn payload(self) -> &'a [u8] {
        self.payload
    }

    /// Return whether this segment carries no payload bytes.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.payload.is_empty()
    }
}

/// Iterator that partitions a borrowed transfer without allocation.
#[derive(Clone, Debug)]
pub struct Segmenter<'a> {
    kind: TransferKind,
    payload: &'a [u8],
    max_payload: usize,
    offset: usize,
    emitted_empty: bool,
}

impl<'a> Segmenter<'a> {
    /// Create a segmenter with a maximum payload byte count per packet.
    pub const fn new(
        kind: TransferKind,
        payload: &'a [u8],
        max_payload: usize,
    ) -> Result<Self, SegmentError> {
        if max_payload == 0 {
            return Err(SegmentError::ZeroPayloadCapacity);
        }

        Ok(Self {
            kind,
            payload,
            max_payload,
            offset: 0,
            emitted_empty: false,
        })
    }

    /// Return the maximum payload bytes carried by one segment.
    #[must_use]
    pub const fn max_payload(&self) -> usize {
        self.max_payload
    }

    /// Return the total number of segments that will be produced.
    #[must_use]
    pub const fn total_segments(&self) -> usize {
        if self.payload.is_empty() {
            1
        } else {
            1 + ((self.payload.len() - 1) / self.max_payload)
        }
    }

    /// Return the number of segments not yet emitted.
    #[must_use]
    pub const fn remaining_segments(&self) -> usize {
        if self.payload.is_empty() {
            if self.emitted_empty { 0 } else { 1 }
        } else {
            let remaining = self.payload.len() - self.offset;
            1 + ((remaining - 1) / self.max_payload)
        }
    }
}

impl<'a> Iterator for Segmenter<'a> {
    type Item = Segment<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.payload.is_empty() {
            if self.emitted_empty {
                return None;
            }
            self.emitted_empty = true;
            return Some(Segment {
                opcode: opcode_for(self.kind, true, true),
                offset: 0,
                payload: &[],
            });
        }

        if self.offset == self.payload.len() {
            return None;
        }

        let start = self.offset;
        let end = start
            .saturating_add(self.max_payload)
            .min(self.payload.len());
        let first = start == 0;
        let last = end == self.payload.len();
        self.offset = end;

        Some(Segment {
            opcode: opcode_for(self.kind, first, last),
            offset: start,
            payload: &self.payload[start..end],
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.remaining_segments();
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for Segmenter<'_> {
    fn len(&self) -> usize {
        self.remaining_segments()
    }
}

fn opcode_for(kind: TransferKind, first: bool, last: bool) -> Opcode {
    match (kind, first, last) {
        (TransferKind::Send, true, true) => Opcode::SendOnly,
        (TransferKind::Send, true, false) => Opcode::SendFirst,
        (TransferKind::Send, false, true) => Opcode::SendLast,
        (TransferKind::Send, false, false) => Opcode::SendMiddle,
        (TransferKind::Write, true, true) => Opcode::RdmaWriteOnly,
        (TransferKind::Write, true, false) => Opcode::RdmaWriteFirst,
        (TransferKind::Write, false, true) => Opcode::RdmaWriteLast,
        (TransferKind::Write, false, false) => Opcode::RdmaWriteMiddle,
        (TransferKind::ReadResponse, true, true) => Opcode::RdmaReadResponseOnly,
        (TransferKind::ReadResponse, true, false) => Opcode::RdmaReadResponseFirst,
        (TransferKind::ReadResponse, false, true) => Opcode::RdmaReadResponseLast,
        (TransferKind::ReadResponse, false, false) => Opcode::RdmaReadResponseMiddle,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_only_opcode_for_single_packet() {
        let data = [1_u8, 2, 3];
        let mut segments = Segmenter::new(TransferKind::Send, &data, 8).unwrap();
        let segment = segments.next().unwrap();

        assert_eq!(segment.opcode(), Opcode::SendOnly);
        assert_eq!(segment.payload(), &data);
        assert!(segments.next().is_none());
    }

    #[test]
    fn selects_first_middle_last_opcodes() {
        let data = [0_u8; 10];
        let mut segments = Segmenter::new(TransferKind::Write, &data, 4).unwrap();

        let first = segments.next().unwrap();
        let middle = segments.next().unwrap();
        let last = segments.next().unwrap();

        assert_eq!(first.opcode(), Opcode::RdmaWriteFirst);
        assert_eq!(first.offset(), 0);
        assert_eq!(first.payload().len(), 4);
        assert_eq!(middle.opcode(), Opcode::RdmaWriteMiddle);
        assert_eq!(middle.offset(), 4);
        assert_eq!(last.opcode(), Opcode::RdmaWriteLast);
        assert_eq!(last.offset(), 8);
        assert_eq!(last.payload().len(), 2);
        assert!(segments.next().is_none());
    }

    #[test]
    fn empty_transfer_still_emits_one_packet() {
        let mut segments = Segmenter::new(TransferKind::ReadResponse, &[], 1024).unwrap();
        let segment = segments.next().unwrap();
        assert_eq!(segment.opcode(), Opcode::RdmaReadResponseOnly);
        assert!(segment.is_empty());
        assert!(segments.next().is_none());
    }

    #[test]
    fn rejects_zero_capacity() {
        assert_eq!(
            Segmenter::new(TransferKind::Send, &[1], 0),
            Err(SegmentError::ZeroPayloadCapacity)
        );
    }
}
