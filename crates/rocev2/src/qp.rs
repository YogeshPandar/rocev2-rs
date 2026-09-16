//! Stable queue-pair handles exposed by the public endpoint.

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
