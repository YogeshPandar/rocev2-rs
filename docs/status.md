# Implementation status

This document separates code that exists from qualification evidence that must be collected on Linux hosts or physical RoCE hardware.

## Implemented and continuously checked

- `no_std`, allocation-free BTH, RETH, AETH, opcode, IPv4/UDP, packet, and ICRC codecs.
- 24-bit PSN arithmetic, cumulative ACK windows, QP transitions, retry/RNR timing, segmentation, reassembly, and fixed rings.
- Fixed-capacity memory registration with full-width lkey/rkey lookup, stale-key rejection, MR leases, access/range/overflow validation, and a small audited raw-memory boundary.
- RC SEND, RDMA WRITE, and RDMA READ requester/responder execution with completions, ACK/NAK/RNR, retries, duplicate suppression, READ replay, and rollover coverage.
- Fixed QPN indexing, requester/responder ready queues, and indexed deadline scheduling without QP-wide packet-path scans.
- Batched packet ownership, batch endpoint progress, batch posting/polling, and the fixed allocation-free packet backend.
- Allocation instrumentation that exercises SEND, WRITE, READ, ACK, retry, RNR, and completion paths and asserts zero steady-state allocation.
- Allocation-free fault injection for loss, duplication, delay, reorder, and corruption.
- Slicing-by-eight ICRC with a bitwise differential reference.
- Linux raw IPv4 and AF_XDP packet backends.
- AF_XDP UMEM, RX/TX/fill/completion rings, generation-checked frame ownership, NEED_WAKEUP, native XDP steering, XSKMAP lifecycle, and untagged Ethernet framing.
- Cargo-fuzz targets for wire decode/roundtrip, memory-registry lifetimes, and RC event streams.
- Miri, ASan, UBSan, deterministic fuzz-smoke, strict Clippy, MSRV, and whole-workspace no-std CI definitions.
- A standalone libibverbs peer and a pure-Rust peer sharing a versioned connection record.
- The Rust interoperability peer can use raw IPv4 or AF_XDP without linking libibverbs into the transport.
- Automated RXE namespace setup and SEND/WRITE/READ matrices in both requester directions, including PSN rollover.
- RXE netem fault, benchmark, and long-soak drivers.
- Requester-side p50, p95, p99, and p99.9 latency output from both interoperability peers.
- Power-of-two QPN shard planning, Linux CPU/NUMA placement discovery, and 100K-QP scale-plan tooling.

## Code present, external qualification still required

The following gates require an environment that normal hosted CI does not provide:

- Run the complete Linux RXE SEND/WRITE/READ matrix in both directions.
- Run the RXE loss, duplicate, delay, reorder, rollover, and long-soak campaigns.
- Run sustained cargo-fuzz, Miri, ASan, and UBSan qualification and retain artifacts.
- Run the privileged XDP verifier/attach path and AF_XDP dataplane on supported NIC queues.
- Qualify AF_XDP zero-copy mode on each supported NIC/driver combination.
- Qualify against physical RoCE RNICs and retain environment metadata and packet captures.
- Run 1, 100, 1K, 10K, and 100K-QP scale tests on target hardware.
- Run reproducible throughput, latency, CPU, cycles/packet, cycles/byte, cache, and allocation measurements.
- Run 24, 48, and 72 hour soak campaigns.

No passing result is claimed until the corresponding workload is executed against the exact release commit.

## Initial release limits

The first production release remains intentionally narrow:

- IPv4 RoCEv2 Reliable Connected transport only.
- SEND, RDMA WRITE, and RDMA READ.
- One SGE per WQE.
- Manual or authenticated out-of-band connection setup.
- Outstanding RDMA READ depth one.
- Untagged Ethernet in the AF_XDP backend.
- One UMEM owned by one AF_XDP socket/queue.
- One Ethernet frame per UMEM chunk.
- No `XDP_USE_SG`, multi-buffer RX/TX, shared UMEM, VLAN/QinQ, RDMA-CM, atomics, multicast, SRQ, XRC, GPU Direct, or congestion-control implementation.

With the default 4096-byte AF_XDP chunk, the complete IPv4 packet limit is 4082 bytes after the Ethernet header. A 4096-byte RoCE path MTU is therefore not supported by the current AF_XDP backend. Use a supported path MTU for AF_XDP qualification.

The crate remains pre-1.0 until the external release gates in `docs/release-qualification.md` have passing evidence.
