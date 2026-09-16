# Architecture

## Layering

The workspace deliberately separates wire compatibility, transport state,
memory safety and operating-system I/O:

- `rocev2-wire`: dependency-free `no_std` BTH/RETH/AETH, IPv4/UDP, packet parser,
  encoder and ICRC. It borrows payloads and never allocates.
- `rocev2-core`: `no_std` PSN arithmetic, QP transitions, segmentation, ACK
  windows, retry policy, fixed-capacity rings and local-QPN indexing.
- `rocev2-memory`: registered-memory ownership, generation-tagged lkey/rkey,
  permission/range/overflow checks and a two-function audited raw-pointer
  boundary.
- `rocev2-io`: complete-IPv4-packet I/O. MockIO is deterministic, raw IPv4 is
  the correctness backend, and AF_XDP is the intended high-throughput backend.
- `rocev2`: endpoint/QP integration and the public API.

## Ownership model

A polling thread owns its endpoint and QP shard. There is no mutex, task per QP,
or channel in the packet path. Work queues, completion queues, packet buffers and
QP tables are fixed-capacity and allocated at endpoint construction.

Each shard uses a fixed open-addressed QPN index to map the destination QPN to
its QP slot. The index is kept at or below 50 percent load, uses contiguous
linear probing, and removes entries with backward shifting so QP churn does not
accumulate tombstones. Packet routing therefore avoids a scan across all QPs
and performs no allocation.

The safe memory-registration API transfers an exclusive slice borrow into the
registry. Network-supplied `(address, rkey, length)` is checked in this order:

1. key lookup and key class;
2. access permission;
3. checked end-address arithmetic;
4. containment in the registered region;
5. copy through the audited raw module.

## Current RC execution model

Each QP supports one active requester WQE and one destination READ resource.
This intentionally corresponds to a negotiated outstanding-read depth of one,
while still allowing fixed queues of future work. SEND and WRITE are segmented
at the negotiated path MTU. READ reserves a PSN for every response packet, as
required by RC, even though only one READ request packet is emitted.

Responder side effects are committed only for the exactly expected PSN.
Duplicates are ACKed/replayed without repeating SEND/WRITE effects; future PSNs
produce a sequence NAK. RNR leaves the expected PSN unchanged.

## Allocation and unsafe-code policy

No steady-state endpoint operation performs a heap allocation. The raw IPv4
backend allocates only while opening sockets. A future AF_XDP backend will map
UMEM and rings during construction, then use caller-owned frames and SPSC rings.

`unsafe` is denied workspace-wide and relaxed only in the two crates that cross
raw pointer or kernel ABI boundaries. Each use is documented next to the
operation and reviewed against the relevant lifetime/range ownership checks.
