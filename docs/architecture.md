# Architecture

## Layering

The workspace deliberately separates wire compatibility, transport state,
memory safety and operating-system I/O:

- `rocev2-wire`: dependency-free `no_std` BTH/RETH/AETH, IPv4/UDP, packet parser,
  encoder and ICRC. It borrows payloads and never allocates.
- `rocev2-core`: `no_std` PSN arithmetic, QP transitions, segmentation, ACK
  windows, retry policy, fixed-capacity rings, local-QPN indexing, intrusive
  ready queues and indexed deadline scheduling.
- `rocev2-memory`: registered-memory ownership, full-width lkey/rkey lookup,
  posted-work leases, permission/range/overflow checks and a small audited
  raw-pointer boundary.
- `rocev2-io`: complete-IPv4-packet I/O, fixed-capacity fault injection, raw
  IPv4 correctness I/O, AF_XDP, and native XDP/XSKMAP steering.
- `rocev2`: endpoint/QP integration and the public API.

## Ownership model

A polling thread owns its endpoint and QP shard. There is no mutex, task per QP,
or channel in the packet path. Work queues, completion queues, packet buffers and
QP tables are fixed-capacity and allocated at endpoint construction.

`QpnShardPlan` partitions the 24-bit application QPN space across a power-of-two
number of independent owners. `plan_workers` combines Linux RX queue discovery,
the process CPU affinity mask, and the NIC NUMA-local CPU list to produce stable
queue/core placement. The control plane creates one endpoint and packet-I/O
queue per owner. Normal packet execution does not cross shard ownership and does
not require a global QP lock or a shared packet queue.

Each shard uses a fixed open-addressed QPN index to map the destination QPN to
its QP slot. The index is kept at or below 50 percent load, uses contiguous
linear probing, and removes entries with backward shifting so QP churn does not
accumulate tombstones. Packet routing therefore avoids a scan across all QPs
and performs no allocation.

## Active-QP scheduling

The endpoint never discovers requester, responder, or timeout work by scanning
the QP table. Each QP slot has requester/responder scheduled flags, and each
ready queue has one intrusive link per possible slot. Posting a WQE, receiving
an ACK/NAK/RNR, accepting a READ request, or expiring a retry makes the affected
QP runnable exactly once. Emitting one segmented packet removes the QP from the
head and, if more work remains, appends it to the tail. Queue insertion,
cancellation and dequeue are therefore O(1) and packet-granularity scheduling
is round-robin among active QPs.

ACK and RNR deadlines use a fixed indexed binary min-heap. There is exactly one
heap entry per QP slot, so repeated timer updates cannot consume extra fixed
capacity. Arm, update, cancellation and expiry are O(log QPs), and the next
deadline is available in O(1). Every entry carries the QP slot, QP generation
and timer sequence. QP generations protect slot reuse, while cancellation and
deadline replacement advance the timer sequence before an obsolete identity can
be accepted.

Consequently, normal `progress` cost is a function of packets, runnable QPs and
expired deadlines processed by that call, not the total number of configured or
idle QPs.

The safe memory-registration API transfers an exclusive slice borrow into the
registry. Network-supplied `(address, rkey, length)` is checked in this order:

1. key lookup and key class;
2. access permission;
3. checked end-address arithmetic;
4. containment in the registered region;
5. copy through the audited raw module, or expose a checked immutable slice tied to the registry borrow.

## Current RC execution model

Each QP supports one active requester WQE and one destination READ resource.
This intentionally corresponds to a negotiated outstanding-read depth of one,
while still allowing fixed queues of future work. SEND and WRITE are segmented
at the negotiated path MTU. READ reserves a PSN for every response packet, as
required by RC, even though only one READ request packet is emitted.

Responder side effects are committed only for the exactly expected PSN.
Duplicates are ACKed/replayed without repeating SEND/WRITE effects; future PSNs
produce a sequence NAK. RNR leaves the expected PSN unchanged.

Requester scheduling distinguishes packet emission from ACK/RNR waiting.
Waiting requests are absent from the requester-ready queue and represented only
by their indexed deadline. A valid ACK, NAK, timeout, or RNR expiry either
completes the WQE, rearms its timer, or puts the same QP back on the ready queue.
Responder READ transmission uses an independent ready queue so requester and
responder wakeups cannot create duplicate queue entries. The data transmit
scheduler alternates requester/responder preference after each successful
packet, while falling back immediately when the preferred class has no work.
This prevents either class from starving the other without adding a table scan.

## AF_XDP foundation

The Linux `afxdp` feature maps and registers one UMEM region, then maps the RX,
TX, fill, and completion rings for one interface queue. RX and TX frames are
partitioned at construction so one hot-path owner can validate descriptor
ownership in constant time. Generation-checked frame handles reject stale or
duplicated application ownership.

The ring wrappers follow AF_XDP's SPSC ownership model. Userspace producers
load the kernel consumer index with acquire ordering and publish their producer
index with release ordering. Userspace consumers load the kernel producer index
with acquire ordering and publish their consumer index with release ordering.
Descriptor access is confined to reserved ring ranges.

`XDP_USE_NEED_WAKEUP` is always requested. RX polling and TX kicks occur only
when the relevant ring flag requests them. The backend supports explicit
zero-copy, explicit copy, and opt-in fallback policies, and verifies the bound
mode through `XDP_OPTIONS`.

AF_XDP sees Ethernet frames while the transport sees complete IPv4 packets.
Transmit prepends an untagged Ethernet II header in UMEM. Receive validates the
EtherType and IPv4 total length directly in the UMEM frame and exposes a
borrowed IPv4 slice without an intermediate packet allocation. Batched SEND,
WRITE, and READ-response payloads are borrowed from checked registered memory
and encoded directly into the final TX frame, removing the intermediate MTU
payload copy. Arbitrary registered memory is still distinct from UMEM, so this
is not payload zero-copy.

The steering layer owns a native XDP BPF link and an XSKMAP. It redirects only
untagged, unfragmented IPv4 packets without IP options whose UDP destination is
4791. Other traffic passes to the normal network stack. Queue registrations use
non-replacing map insertion and are removed before the AF_XDP socket descriptor
is closed. VLAN, QinQ, multi-buffer descriptors, and `XDP_USE_SG` remain
intentionally unsupported.

## Allocation and unsafe-code policy

No steady-state endpoint operation performs a heap allocation. The raw IPv4
backend allocates only while opening sockets. AF_XDP allocates its UMEM mapping,
ring mappings, and fixed frame metadata during construction, then uses only
caller-owned frames, fixed-capacity metadata, and SPSC rings on the packet path.

`unsafe` is denied workspace-wide and relaxed only in the crates that cross raw
pointer or kernel ABI boundaries. AF_XDP unsafe operations are centralized in
UMEM/ring mappings, descriptor access, and socket syscalls. Each operation
documents pointer ownership, range, alignment, and mapping lifetime invariants.
