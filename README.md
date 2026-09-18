# rocev2-rs

A pure-Rust userspace RoCEv2 transport for IPv4 Reliable Connected queue pairs.
The data path implements the transport itself; it does not forward SEND, RDMA
WRITE, or RDMA READ operations to libibverbs, librdmacm, UCX, rdma-core, or
Linux RXE.

> **Status: pre-1.0 qualification candidate.** The narrow IPv4 RC transport,
> fixed-capacity scheduling/memory model, batched packet path, AF_XDP backend,
> zero-allocation verification, fuzz/safety targets, interoperability peers,
> RXE fault/benchmark/soak harnesses, and scale/NUMA tooling are implemented.
> Release still requires executed RXE, RNIC, AF_XDP, sustained safety, scale,
> performance, and long-soak evidence on the exact release commit.

## Workspace

| Crate | Purpose |
|---|---|
| `rocev2-wire` | `no_std`, allocation-free BTH/RETH/AETH, IPv4/UDP, and ICRC |
| `rocev2-core` | `no_std` PSN, QP, retry, segmentation, fixed-ring, QPN-index, and active-QP scheduling primitives |
| `rocev2-memory` | full-width lkey/rkey registration, MR leases, and checked access |
| `rocev2-io` | packet I/O, fixed fault injection, raw IPv4, AF_XDP, and XDP/XSKMAP steering |
| `rocev2` | endpoint composition and fixed-capacity RC posted-work engine |

The current scope is deliberately narrow: RoCEv2 over IPv4, RC QPs, one SGE
per WQE, and SEND/RDMA WRITE/RDMA READ. Connection metadata is exchanged out of
band; RDMA-CM is not part of the current implementation.

## Posted-work engine

`RcEndpoint` owns a fixed QP table, an open-addressed local-QPN index, fixed
SQ/RQ/CQ rings, requester and responder ready queues, an indexed deadline heap,
a checked memory registry, and scalar compatibility scratch space. Batched TX
borrows validated registered-memory payloads directly into final backend frames.
Incoming packets
use the QPN index instead of scanning every live QP. Posting and protocol events
schedule a QP exactly once; progress pops only runnable QPs and expired
deadlines rather than walking the QP table. Segmented transfers return to the
tail of their ready queue, providing packet-granularity round-robin fairness.
When requester and responder work are both runnable, the transmit scheduler
alternates class preference so sustained READ responses cannot starve local
requester traffic.

Ready-queue insertion, cancellation, and removal are O(1). Timer arm, update,
cancellation, and expiry are O(log QPs), while reading the next deadline is
O(1). QPs and their rings allocate only on the control path. Once the endpoint,
QPs, and MRs exist, posting, polling, packet parsing/encoding, ACK processing,
memory access, scheduling, retries, and batch packet encoding do not perform
transport-owned heap allocations.

The default endpoint reserves 2,048 QPN-index entries for 1,024 QP slots. A
custom `QPN_INDEX` capacity must be a power of two and at least twice `QPS`,
keeping the table at or below 50 percent load while QPs are created, removed,
and reconfigured.

```rust,no_run
use std::net::Ipv4Addr;
use rocev2::{
    AccessFlags, Ipv4Path, PathMtu, Psn, QpConfig, QpState, RcEndpoint,
    RcEndpointConfig, RcQpConfig, Sge, SystemKeyGenerator, WorkRequest,
};
use rocev2::io::{RawIpv4Config, RawIpv4Socket};

type HostEndpoint<'a> = RcEndpoint<'a, RawIpv4Socket, 1024, 4096, 128, 128, 256>;

# fn run() -> Result<(), Box<dyn std::error::Error>> {
let local_ip = [192, 0, 2, 10];
let remote_ip = [192, 0, 2, 20];
let io = RawIpv4Socket::bind(RawIpv4Config {
    bind_address: Ipv4Addr::from(local_ip),
    max_ipv4_packet: 4600,
})?;
let mut endpoint = HostEndpoint::new(
    io,
    RcEndpointConfig {
        maximum_packet_size: 4600,
        ticks_per_second: 1_000_000_000,
        memory_key_seed: 0x5eed,
    },
)?;

let mut buffer = [0_u8; 4096];
let mut keys = SystemKeyGenerator::new()?;
let mr = endpoint.register_memory_with_key_generator(
    &mut buffer,
    AccessFlags::LOCAL_WRITE
        | AccessFlags::REMOTE_WRITE
        | AccessFlags::REMOTE_READ,
    &mut keys,
)?;

// QPNs, PSNs, MTU, rkey, and remote virtual address come from an
// authenticated out-of-band control plane.
let qp = endpoint.create_qp(RcQpConfig {
    transport: QpConfig {
        local_qpn: 0x100,
        remote_qpn: 0x200,
        send_psn: Psn::new_truncated(0x123456),
        receive_psn: Psn::new_truncated(0x654321),
        path_mtu: PathMtu::Mtu1024,
        retry_count: 3,
        rnr_retry_count: 3,
        timeout: 14,
    },
    path: Ipv4Path::new(local_ip, remote_ip, 50_000),
    rnr_nak_timer: 12,
})?;
endpoint.transition_qp(qp, QpState::Init)?;
endpoint.transition_qp(qp, QpState::Rtr)?;
endpoint.transition_qp(qp, QpState::Rts)?;

endpoint.post_work(
    qp,
    WorkRequest::write(
        1,
        Sge::new(mr.address(), 4096, mr.lkey()),
        0x7f00_0000_0000,
        0x1234_5678,
        true,
    ),
)?;

let mut receive_packet = [0_u8; 4600];
let mut transmit_packet = [0_u8; 4600];
loop {
    let now = monotonic_nanoseconds();
    endpoint.progress(now, &mut receive_packet, &mut transmit_packet)?;
    if let Some(completion) = endpoint.poll_completion(qp)? {
        completion.is_success().then_some(()).ok_or("RDMA operation failed")?;
        break;
    }
}
# Ok(())
# }
# fn monotonic_nanoseconds() -> u64 { 0 }
```

Raw IPv4 requires `CAP_NET_RAW` and is the correctness/reference backend, not
the intended final high-throughput path.

## Correctness model

Incoming network addresses are never dereferenced directly. Every local or
remote operation passes through exact key lookup, access checks, checked address
arithmetic, registered-range containment, and only then the audited raw copy
boundary. Responder side effects occur only for the exactly expected PSN;
duplicates are ACKed or replayed without repeating writes, while future PSNs
produce a sequence NAK. RDMA READ reserves the complete response PSN span before
the request is transmitted.

See [implementation status](docs/status.md), [architecture](docs/architecture.md),
[AF_XDP backend](docs/afxdp.md), [qualification tooling](docs/qualification.md),
[release qualification](docs/release-qualification.md), and
[protocol sources](docs/protocol-sources.md) for the current release boundary
and the primary references used by the implementation.

## Validation

```text
cargo fmt --all --check
cargo test --workspace --all-features --all-targets
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo check --workspace --no-default-features --target thumbv7em-none-eabihf
```

Dual-licensed under MIT or Apache-2.0.
