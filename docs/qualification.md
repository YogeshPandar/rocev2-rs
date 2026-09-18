# Qualification tooling

This change keeps qualification infrastructure outside the production packet path.
The portable crates remain usable without `std`; verbs is a separate test peer,
not a transport dependency. Performance numbers and hardware qualification are
not implied by the presence of a harness.

## Scope

- Count allocation, zeroed-allocation, reallocation, and deallocation calls during
  fixed-backend SEND, WRITE, READ, retry, RNR, and completion processing.
- Fuzz packet codecs, RC event streams, and memory-registry lifetimes with bounded
  storage, plus Miri and sanitizer jobs.
- Exchange versioned connection metadata with a standalone libibverbs peer and
  exercise both requester directions through an isolated RXE namespace harness.
- Provide single-owner QPN sharding, optional Linux CPU/NUMA placement helpers,
  and reproducible microbenchmark, end-to-end, and scale drivers.

## Evidence policy

Source review, compilation, unit tests, fuzz campaigns, RXE interoperability,
and RNIC performance are separate gates. Record the exact commit and environment
for every qualification run. Do not describe unexecuted workloads as passing.

## Primary references

- Rust `GlobalAlloc`: https://doc.rust-lang.org/std/alloc/trait.GlobalAlloc.html
- Miri: https://github.com/rust-lang/miri
- Rust sanitizers: https://doc.rust-lang.org/unstable-book/compiler-flags/sanitizer.html
- cargo-fuzz: https://rust-fuzz.github.io/book/cargo-fuzz.html
- rdma-core: https://github.com/linux-rdma/rdma-core
- AF_XDP: https://docs.kernel.org/networking/af_xdp.html
- NUMA policy: https://docs.kernel.org/admin-guide/mm/numa_memory_policy.html
