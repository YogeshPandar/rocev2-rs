# Implementation status

This document separates implemented, continuously tested behavior from work that requires Linux/kernel facilities or physical RoCE hardware and therefore must not be claimed before qualification runs exist.

## Implemented and covered by workspace tests

- `no_std`, allocation-free BTH, RETH, AETH, opcode, IPv4/UDP, packet, and ICRC codecs with strict length, reserved-bit, padding, header-combination, and ICRC validation.
- 24-bit serial PSN arithmetic, cumulative ACK windows, multi-PSN RDMA READ reservations, QP transitions, retry budgets, RNR timing, and fixed rings.
- Fixed-capacity memory registration with generation-tagged lkey/rkey values, permission/range/overflow checks, and an audited raw-copy boundary.
- Backend-neutral complete-IPv4 packet I/O, deterministic mock I/O, and a Linux raw-IPv4 correctness backend.
- Fixed-capacity posted SEND, RDMA WRITE, and RDMA READ execution with one SGE per WQE and CQ generation for requester and receive work.
- Fixed-capacity open-addressed local-QPN routing with collision-safe deletion, bounded load factor, and no per-packet scan across the QP table.
- Fixed-capacity requester/responder ready queues and an indexed deadline min-heap, eliminating QP-table scans for transmit work and retry timers while preserving packet-granularity round-robin fairness within and across requester/responder traffic classes.
- Batched packet ownership APIs, bounded endpoint batch progress, batch WQE posting, batch receive posting, completion polling, and the fixed allocation-free test backend.
- MTU segmentation/reassembly, positive ACKs, sequence/access/invalid-request NAKs, RNR NAKs, timeout and NAK retry scheduling, duplicate suppression, and RDMA READ response replay.
- Two-endpoint deterministic tests for segmented SEND, WRITE followed by READ, RNR recovery, packet-loss timeout retransmission, and remote-access failure, plus active-QP and requester/responder class fairness, multiple simultaneous deadline expiry, reset cancellation, and randomized scheduler-model differential tests.
- AF_XDP configuration validation and Ethernet framing tests, including VLAN/QinQ rejection and exact IPv4 length recovery from padded Ethernet frames.

## Implemented but not yet qualified as production-ready

- The Linux AF_XDP foundation behind the `afxdp` feature implements UMEM allocation/registration, RX/TX/fill/completion ring mappings, generation-checked frame ownership, `XDP_USE_NEED_WAKEUP`, explicit zero-copy/copy bind policy, untagged Ethernet framing, direct borrowed UMEM RX parsing, and fixed-capacity steady-state frame recycling.
- AF_XDP still requires a separately installed XDP redirect program and XSKMAP. Hardware zero-copy behavior has not yet been qualified on supported NICs.
- The raw IPv4 backend exercises the complete transport but has not yet been certified against `rdma_rxe` on two Linux endpoints.
- The steady-state design uses fixed storage, but allocator-instrumented tests still need to prove zero allocations across the normal packet path.
- Parser/state-machine unit and property tests exist; long-running coverage-guided fuzz campaigns and corpus management are still required.

## Not yet complete

- Project-owned XDP program, XSKMAP lifecycle, queue steering, shared-UMEM policy, multi-buffer/scatter-gather support, and UMEM-backed application buffers.
- Automated Linux `rdma_rxe` SEND/WRITE/READ interoperability in both relevant directions, including loss, reorder, duplicate, rollover, malformed, and bad key/address cases.
- Hardware qualification against NVIDIA/Mellanox, Intel, Broadcom, and other supported RoCE NICs.
- Comparative RXE benchmarks for throughput, latency distribution, allocations/op, cycles/packet, CPU/byte, and cache behavior.
- Per-core QP sharding, NUMA placement, and 100K-QP scale qualification.

The crate remains pre-1.0 until the interoperability, safety, fuzzing, zero-allocation, AF_XDP steering/qualification, and performance gates above are satisfied.
