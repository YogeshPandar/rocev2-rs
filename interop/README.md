# Linux RXE and RNIC interoperability

The production transport never links libibverbs. Interoperability uses two
separate executables:

- `interop/rxe-peer`: a C/libibverbs RC reference peer;
- `interop/rust-peer`: the real pure-Rust `RcEndpoint` over the raw IPv4 backend.

Build both peers:

```text
interop/scripts/build-peers.sh
```

On a disposable Linux host with `rdma_rxe`, `iproute2`, `libibverbs`, network
namespace support, and root privileges, run the complete software matrix:

```text
sudo -E interop/scripts/rxe-matrix.sh
```

The harness creates two network namespaces and a veth pair, attaches RXE to the
verbs side with `rdma link add`, then tests SEND, WRITE, and READ with either
peer as requester. The default matrix includes every RC MTU, packet-boundary
sizes, 64 KiB, 1 MiB, and a starting PSN of `0xfffff0` to force rollover.
Override `ROCEV2_SIZES`, `ROCEV2_MTUS`, or `ROCEV2_ITERATIONS` for targeted or
long runs.

For physical RNIC qualification, run the same two peer binaries on separate
hosts connected through the target RoCE network. Use
`interop/scripts/capture-environment.sh` on each host and retain its output with
the peer logs and packet captures. The verbs peer accepts any libibverbs RC
device exposing an IPv4-mapped RoCEv2 GID; no hardware-specific protocol code
is used.

The control channel is test-only TCP metadata exchange, not RDMA-CM. It must not
be treated as authentication for production connection parameters.
