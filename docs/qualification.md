# Qualification tooling

Qualification infrastructure is kept outside the production packet path. The portable crates remain usable without `std`; libibverbs is used only by a separate reference peer.

## Allocation verification

`crates/rocev2/tests/allocation.rs` installs a counting `GlobalAlloc`, constructs endpoints and registered memory before measurement, then exercises steady-state SEND, WRITE, READ, retries, RNR, and completion processing.

~~~text
cargo test -p rocev2 --test allocation --all-features
~~~

A passing test means the covered steady-state transport paths performed zero allocation, zero zeroed-allocation, and zero reallocation calls during the measured region.

## Safety tooling

The `fuzz/` package provides four cargo-fuzz targets:

~~~text
wire_decode
wire_roundtrip
memory_registry
rc_events
~~~

The safety workflow also defines Miri and sanitizer jobs. A deterministic fuzz-oracle smoke test runs separately so ordinary logic regressions are caught without waiting for a coverage-guided campaign.

## RXE and RNIC interoperability

`interop/rxe-peer` is the libibverbs reference peer. `interop/rust-peer` executes the real Rust RC engine. Both use the same versioned 64-byte connection record.

The RXE harness creates disposable namespaces, a veth pair, and an `rdma_rxe` device, then covers SEND, WRITE, and READ with either implementation acting as requester.

~~~text
sudo -E interop/scripts/rxe-matrix.sh
sudo -E interop/scripts/rxe-fault-matrix.sh
sudo -E interop/scripts/rxe-benchmark.sh
~~~

For long runs:

~~~text
ROCEV2_SOAK_SECONDS=86400 sudo -E interop/scripts/rxe-soak.sh
~~~

The Rust peer defaults to raw IPv4. Set `ROCEV2_BACKEND=afxdp` plus the AF_XDP interface, queue, and MAC environment variables for hardware AF_XDP qualification.

## Scale and placement

The standalone qualification driver supplies deterministic microbenchmarks, a 100K-QP shard plan, and Linux queue/CPU/NUMA placement discovery.

~~~text
cargo run --release --manifest-path tools/qualification/Cargo.toml -- micro
cargo run --release --manifest-path tools/qualification/Cargo.toml -- scale 128
cargo run --release --manifest-path tools/qualification/Cargo.toml -- placement eth0 8
~~~

The placement helper is control-plane code. It does not add locks, sysfs reads, or allocation to packet execution.

## Evidence policy

Compilation, unit tests, fuzzing, RXE interoperability, AF_XDP execution, RNIC qualification, soak testing, and performance are independent gates. Record the exact commit, kernel, rdma-core version, NIC, firmware, MTU, CPU affinity, NUMA placement, and raw result files for every release run.

The complete release procedure is in `release-qualification.md`.

## Primary references

- Rust `GlobalAlloc`: https://doc.rust-lang.org/std/alloc/trait.GlobalAlloc.html
- Miri: https://github.com/rust-lang/miri
- Rust sanitizers: https://doc.rust-lang.org/unstable-book/compiler-flags/sanitizer.html
- cargo-fuzz: https://rust-fuzz.github.io/book/cargo-fuzz.html
- rdma-core: https://github.com/linux-rdma/rdma-core
- Linux AF_XDP: https://docs.kernel.org/networking/af_xdp.html
- Linux NUMA policy: https://docs.kernel.org/admin-guide/mm/numa_memory_policy.html
