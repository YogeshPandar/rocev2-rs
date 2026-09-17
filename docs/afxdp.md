# AF_XDP backend

The `afxdp` feature provides the Linux AF_XDP foundation for the packet I/O layer. It keeps the RC transport API expressed in complete IPv4 packets while moving Ethernet framing, UMEM ownership, and kernel ring handling into `rocev2-io`.

## Scope

This phase implements:

- page-aligned UMEM allocation with optional hugetlb backing;
- fixed 2 KiB or 4 KiB aligned chunks and explicit RX/TX frame partitioning;
- RX, TX, fill, and completion ring mappings;
- acquire/release ordering for kernel/user producer and consumer indices;
- generation-checked application frame handles;
- `XDP_USE_NEED_WAKEUP` polling and TX kick behavior;
- explicit zero-copy, copy, or opt-in fallback bind policy;
- untagged Ethernet II encapsulation for IPv4;
- direct borrowed IPv4 parsing from UMEM on RX;
- allocation-free batch receive, transmit, recycle, and completion processing after construction.

The backend uses the AF_XDP structures and constants exported by the pinned `libc` crate. It does not duplicate Linux UAPI layouts in project code.

## Construction

Enable the feature and construct one socket per NIC queue:

```rust,no_run
use rocev2::io::{AfxdpConfig, AfxdpSocket, EthernetPath};

# fn run() -> Result<(), Box<dyn std::error::Error>> {
let ethernet = EthernetPath::new(
    [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
    [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
);
let config = AfxdpConfig::new(2, 0, ethernet);
let socket = AfxdpSocket::bind(config)?;
assert!(socket.max_ipv4_packet() >= 1500);
# Ok(())
# }
```

`interface_index` is the Linux interface index and `queue_id` selects one hardware RX queue. The caller obtains MAC addresses and connection metadata through the control plane. This backend does not implement ARP, neighbor discovery, or RDMA-CM.

AF_XDP UMEM is pinned by the kernel during registration. The process therefore needs an adequate `RLIMIT_MEMLOCK` and the privileges required by the deployment to create and bind AF_XDP sockets.

## XDP steering requirement

`AfxdpSocket` does not install an XDP program and does not manage an XSKMAP in this phase. A compatible XDP program must redirect the target queue to the socket before traffic can arrive. XDP steering and XSKMAP lifecycle are the next production phase.

The transport logic remains outside the XDP program. Steering should only identify eligible RoCEv2 UDP traffic and redirect it to the correct queue/socket.

## Frame ownership

RX frames follow this ownership sequence:

```text
fill ring -> kernel RX -> application RX -> fill ring
```

TX frames follow this sequence:

```text
free TX -> application TX -> TX ring -> completion ring -> free TX
```

Application handles carry a frame generation. A stale or duplicated handle is rejected before it can access or recycle a frame. Kernel descriptors are range checked against UMEM and against the frame pool assigned to their direction.

The backend keeps RX and TX frame pools disjoint. This makes ownership checks constant time and avoids a shared hot-path allocator.

## Packet layout

AF_XDP operates on Ethernet frames. The public transport still reads and writes complete IPv4 packets:

```text
TX: [ethernet header][complete IPv4 packet]
RX: [ethernet header][borrowed complete IPv4 packet]
```

Only untagged Ethernet II with EtherType `0x0800` is accepted in this phase. VLAN and QinQ frames are rejected and counted. The destination and source MAC addresses are supplied by `EthernetPath`.

On RX, the backend validates the Ethernet type and IPv4 header directly in the UMEM frame, then returns a borrowed IPv4 slice. Ethernet padding is excluded using the IPv4 total-length field. No temporary packet allocation or intermediate `Vec` is created.

## Ring synchronization

Each AF_XDP ring has one userspace owner. The implementation follows the kernel SPSC model:

- producers read the consumer index with acquire ordering and publish the producer index with release ordering;
- consumers read the producer index with acquire ordering and publish the consumer index with release ordering;
- descriptors are accessed only inside a range reserved by the corresponding ring indices.

`XDP_USE_NEED_WAKEUP` is always requested. RX polling and TX `sendto` kicks occur only when the corresponding ring flag says that the kernel requires a wakeup. `EINTR` is retried. Wakeup errors are counted instead of invalidating frame ownership after a descriptor has already been published.

## Zero-copy policy

`AfxdpConfig::bind_mode` has three explicit policies:

- `ZeroCopy` requires `XDP_ZEROCOPY` and fails if the driver cannot provide it;
- `Copy` requires `XDP_COPY`;
- `AllowCopyFallback` permits the kernel's normal fallback behavior.

After bind, `AfxdpSocket::is_zero_copy()` reports the mode returned by `XDP_OPTIONS`.

This only describes packet ownership between the NIC/kernel and UMEM. Registered application memory used by RC SEND, WRITE, or READ is still copied into or out of UMEM by the current transport. UMEM-backed application buffers belong to the later XDP production phase and must be documented separately before the project claims payload zero-copy.

## Current limits

The foundation intentionally does not enable `XDP_USE_SG`. Each Ethernet frame must therefore fit in one UMEM chunk. With the default 4096-byte chunk and zero headroom, the maximum complete IPv4 packet is 4082 bytes because 14 bytes are reserved for Ethernet. A RoCE path MTU of 4096 cannot be qualified on this backend until scatter/gather or a larger supported chunk mode is implemented.

Other current limits are:

- no VLAN or QinQ support;
- no shared UMEM across sockets;
- no multi-buffer RX/TX descriptors;
- no XDP program or XSKMAP management;
- no UMEM-backed application buffer API;
- no hardware or RXE AF_XDP qualification yet.

These are deliberate phase boundaries, not implied support.

## References

Implementation behavior is reviewed against the Linux kernel AF_XDP documentation and `include/uapi/linux/if_xdp.h`. Rust ownership of file descriptors uses `std::os::fd::OwnedFd`, and ring synchronization uses `std::sync::atomic` acquire/release ordering. Ethernet II IPv4 framing follows RFC 894.

See `protocol-sources.md` for the pinned primary references.
