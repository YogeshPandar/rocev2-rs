# rocev2-rs

A pure-Rust userspace RoCEv2 transport for IPv4 Reliable Connected queue pairs.
The data path implements protocol state itself; it does not forward operations
to libibverbs, librdmacm, UCX, rdma-core, or Linux RXE.

> **Status:** pre-1.0 engineering preview. The wire/core/memory layers and a
> deterministic endpoint engine are implemented and tested in software. Do not
> use it to expose untrusted memory or production traffic until RXE and hardware
> interoperability suites, long-running loss/reorder tests, fuzzing, and an
> external unsafe-code review are complete.

## Workspace

| Crate | Purpose |
|---|---|
| `rocev2-wire` | `no_std`, allocation-free BTH/RETH/AETH, IPv4/UDP and ICRC |
| `rocev2-core` | `no_std` RC PSN/QP/retry/segmentation state machines |
| `rocev2-memory` | checked lkey/rkey registration and remote access |
| `rocev2-io` | MockIO, raw IPv4 and AF_XDP packet backends |
| `rocev2` | endpoint, QP table and native Rust API |

The implemented v1 scope is IPv4 RoCEv2 RC SEND, RDMA WRITE and RDMA READ,
including MTU segmentation, PSN rollover arithmetic, ACK/NAK/RNR handling,
retries, duplicate suppression, READ replay and strict ICRC verification.
Connection metadata is exchanged out of band; RDMA-CM is not part of this
release.

## Example

```rust,no_run
use rocev2::{
    Access, Endpoint, EndpointConfig, Ipv4Path, PathMtu, Psn, QpConfig, Sge,
    WorkRequest, WorkRequestKind,
};
use rocev2::io::{RawIpv4Config, RawIpv4Socket};

type HostEndpoint<'a> = Endpoint<'a, RawIpv4Socket, 1024, 4096, 256, 256, 512, 8192>;

# fn run() -> Result<(), Box<dyn std::error::Error>> {
let local_ip = [192, 0, 2, 10];
let remote_ip = [192, 0, 2, 20];
let socket = RawIpv4Socket::open(RawIpv4Config::new(local_ip))?;
let mut endpoint = HostEndpoint::new(socket, EndpointConfig::new(local_ip, 0x5eed))?;

let mut buffer = [0_u8; 4096];
let mr = endpoint.register_memory(
    &mut buffer,
    Access::LOCAL_READ | Access::LOCAL_WRITE,
)?;

// QPNs, PSNs, MTU, rkey and remote virtual address come from an out-of-band
// authenticated control plane.
let qp = endpoint.create_connected_qp(
    QpConfig {
        local_qpn: 0x100,
        remote_qpn: 0x200,
        send_psn: Psn::wrapping(0x123456),
        receive_psn: Psn::wrapping(0x654321),
        path_mtu: PathMtu::Mtu1024,
        ack_timeout_ticks: 1_000_000,
        retry_count: 3,
        rnr_retry_count: 3,
        min_rnr_timer: 12,
    },
    Ipv4Path::new(local_ip, remote_ip, 50_000),
)?;

endpoint.post_send(
    qp,
    WorkRequest {
        work_request_id: 1,
        local: Sge {
            address: mr.address,
            length: 4096,
            local_key: mr.local_key,
        },
        kind: WorkRequestKind::Write {
            remote_address: 0x7f00_0000_0000,
            remote_key: 0x1234_5678,
        },
        solicited: false,
    },
)?;

loop {
    endpoint.poll(monotonic_nanoseconds())?;
    if let Some(completion) = endpoint.poll_completion(qp)? {
        assert_eq!(completion.work_request_id, 1);
        break;
    }
}
# Ok(())
# }
# fn monotonic_nanoseconds() -> u64 { 0 }
```

Raw IPv4 requires `CAP_NET_RAW` and is intended as a correctness/reference
backend. AF_XDP setup requires a bound queue and an XDP program/XSKMAP; see
[`docs/af-xdp.md`](docs/af-xdp.md).

## Validation

```text
cargo fmt --all --check
cargo test --workspace --all-features --all-targets
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo check -p rocev2-wire --target thumbv7em-none-eabihf
cargo check -p rocev2-core --target thumbv7em-none-eabihf
cargo check -p rocev2-memory --target thumbv7em-none-eabihf
```

Protocol sources and exact Linux interoperability references are recorded in
[`docs/protocol-sources.md`](docs/protocol-sources.md). The architecture and
unsafe-code policy are in [`docs/architecture.md`](docs/architecture.md).

Dual-licensed under MIT or Apache-2.0.
