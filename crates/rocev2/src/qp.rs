//! Stable queue-pair handles exposed by the public endpoint.

use crate::ApiError;
use rocev2_core::{QpnInsertError, QpnTable, StateTransitionError};

/// Opaque, generation-checked queue-pair handle.
///
/// Removing and reusing a table slot changes its generation, so stale handles
/// cannot accidentally address a newly created queue pair.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct QpHandle {
    slot: u32,
    generation: u32,
}

impl QpHandle {
    pub(crate) const fn new(slot: u32, generation: u32) -> Self {
        Self { slot, generation }
    }

    pub(crate) const fn slot(self) -> u32 {
        self.slot
    }

    pub(crate) const fn generation(self) -> u32 {
        self.generation
    }
}

pub(crate) fn validate_qpn_index<const QPS: usize, const QPN_INDEX: usize>() -> Result<(), ApiError>
{
    if QpnTable::<QPN_INDEX>::supports_entries(QPS) {
        Ok(())
    } else {
        Err(ApiError::InvalidQpnIndexCapacity {
            qp_capacity: QPS,
            index_capacity: QPN_INDEX,
        })
    }
}

#[inline]
pub(crate) fn qpn_slot<const N: usize>(table: &QpnTable<N>, qpn: u32) -> Option<usize> {
    table.get(qpn).and_then(|slot| usize::try_from(slot).ok())
}

pub(crate) fn insert_qpn<const N: usize>(
    table: &mut QpnTable<N>,
    qpn: u32,
    slot: usize,
) -> Result<u32, ApiError> {
    let slot = u32::try_from(slot).map_err(|_| ApiError::QpTableFull)?;
    match table.insert(qpn, slot) {
        Ok(()) => Ok(slot),
        Err(QpnInsertError::InvalidQpn(qpn)) => {
            Err(StateTransitionError::InvalidLocalQpn(qpn).into())
        }
        Err(QpnInsertError::Duplicate(qpn)) => Err(ApiError::DuplicateLocalQpn(qpn)),
        Err(QpnInsertError::Full) => Err(ApiError::QpnIndexFull),
    }
}
