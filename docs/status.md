# Implementation status

This document distinguishes implemented, continuously tested foundations from
hardware-dependent work that must not be claimed before interoperability runs.

## Implemented and covered by workspace tests

- `no_std`, allocation-free BTH, RETH, AETH, opcode, IPv4/UDP, packet, and ICRC
  codecs.
- Strict length, reserved-bit, padding, header-combination, and ICRC validation.
- 24-bit PSN serial arithmetic, cumulative ACK windows, receive ordering, QP
  state transitions, retry budgets, RNR timing, and borrowed segmentation.
- Fixed-capacity registered-memory table with lkey/rkey, access, overflow, and
  range checks before the audited unsafe copy boundary.
- Backend-neutral complete-IPv4-packet I/O, deterministic mock I/O, and a
  Linux raw IPv4 reference backend.
- Public endpoint composition for QP lifecycle, routing, PSN bookkeeping, and
  strict complete-packet transmit/receive.

## Not yet complete

- Posted SEND, RDMA WRITE, and RDMA READ work execution and completion queues.
- ACK/NAK/RNR packet generation, retransmission scheduling, and reassembly in
  the public endpoint.
- AF_XDP UMEM and ring backend.
- Linux RXE and hardware-NIC interoperability qualification.
- Packet/state-machine fuzz campaigns and comparative performance results.

The crate remains pre-1.0 until the interoperability, safety, fuzzing, and
performance gates in the project README are satisfied.
