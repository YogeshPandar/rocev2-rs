# Linux RXE and RNIC interoperability

The production transport never links libibverbs. Interoperability uses two
separate executables:

- `interop/rxe-peer`: a C/libibverbs RC reference peer;
- `interop/rust-peer`: the real pure-Rust `RcEndpoint`, selectable between
  raw IPv4 and AF_XDP packet I/O.

Build both peers:

~~~text
bash interop/scripts/build-peers.sh
~~~

## RXE correctness matrix

On a disposable Linux host with `rdma_rxe`, iproute2, libibverbs, network
namespace support, and root privileges:

~~~text
sudo -E bash interop/scripts/rxe-matrix.sh
~~~

The harness creates two network namespaces and a veth pair, attaches RXE to the
verbs side with `rdma link add`, then tests SEND, WRITE, and READ with either
peer as requester. The default matrix includes every RC MTU, packet-boundary
sizes, 64 KiB, 1 MiB, and a starting PSN of `0xfffff0` to force rollover.

Override `ROCEV2_SIZES`, `ROCEV2_MTUS`, `ROCEV2_ITERATIONS`, or
`ROCEV2_PSN` for targeted runs.

## Fault, benchmark, and soak drivers

The matrix accepts a Linux netem profile through `ROCEV2_NETEM`. The packaged
fault driver runs representative loss, duplicate, delay, and reorder profiles:

~~~text
sudo -E bash interop/scripts/rxe-fault-matrix.sh
~~~

The benchmark driver uses larger iteration counts and records machine-readable
requester latency distributions:

~~~text
ROCEV2_ITERATIONS=1000 sudo -E bash interop/scripts/rxe-benchmark.sh
~~~

The soak driver repeats complete namespace, QP, MR, and transfer lifecycles:

~~~text
ROCEV2_SOAK_SECONDS=86400 sudo -E bash interop/scripts/rxe-soak.sh
~~~

Run 24, 48, and 72 hour campaigns directly on a qualification host and retain
all result directories.

## AF_XDP peer mode

The Rust peer defaults to the raw IPv4 reference backend. Hardware AF_XDP
qualification uses the same RC engine and control protocol with:

~~~text
ROCEV2_BACKEND=afxdp
ROCEV2_IFINDEX=2
ROCEV2_QUEUE=0
ROCEV2_QUEUE_COUNT=1
ROCEV2_SOURCE_MAC=02:00:00:00:00:01
ROCEV2_DEST_MAC=02:00:00:00:00:02
~~~

Zero-copy bind mode is required by default. Set `ROCEV2_ALLOW_COPY_FALLBACK`
only for an explicitly labeled fallback test. The AF_XDP process needs the
deployment privileges, memlock allowance, queue ownership, and NIC/driver
support required by Linux AF_XDP.

The current one-frame backend cannot carry a 4096-byte RoCE path MTU with the
default 4096-byte UMEM chunk because the Ethernet header also occupies the
frame. Use a supported path MTU for AF_XDP qualification.

## Physical RNIC qualification

For physical RNIC qualification, run the same peer binaries on hosts connected
through the target RoCE network. Use:

~~~text
bash interop/scripts/capture-environment.sh <interface>
~~~

Retain the output with peer logs, latency JSON lines, performance counters, and
packet captures. The verbs peer accepts a libibverbs RC device exposing an
IPv4-mapped RoCEv2 GID; no hardware-specific protocol code enters the Rust
transport.

The control channel is test-only TCP metadata exchange, not RDMA-CM. It must not
be treated as authentication for production connection parameters.
