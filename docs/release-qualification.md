# Release qualification

This checklist is the execution boundary for a 1.0 release. The repository contains the code and harnesses needed to perform these gates, but a gate is complete only when its evidence was produced from the exact release commit.

## 1. Hosted correctness gates

Run the normal workspace checks:

~~~text
cargo fmt --all --check
cargo test --workspace --all-features --all-targets
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo check --workspace --no-default-features --target thumbv7em-none-eabihf
cargo +1.85.0 check --workspace --all-features
~~~

Run the standalone hosted tools:

~~~text
cargo test --locked --manifest-path interop/rust-peer/Cargo.toml
cargo clippy --locked --manifest-path interop/rust-peer/Cargo.toml --all-targets -- -D warnings
cargo test --locked --manifest-path tools/qualification/Cargo.toml
cargo clippy --locked --manifest-path tools/qualification/Cargo.toml --all-targets -- -D warnings
make -C interop/rxe-peer clean test
python3 -m unittest discover -s interop/tests -v
~~~

## 2. Zero-allocation gate

~~~text
cargo test -p rocev2 --test allocation --all-features
~~~

Do not infer arbitrary application zero-copy from this result. This gate verifies transport-owned steady-state allocations for the covered fixed-backend execution paths.

## 3. Safety gate

Run every cargo-fuzz target for a sustained campaign and preserve corpus/artifact directories:

~~~text
cargo +nightly fuzz run wire_decode -- -max_len=8192
cargo +nightly fuzz run wire_roundtrip -- -max_len=8192
cargo +nightly fuzz run memory_registry -- -max_len=8192
cargo +nightly fuzz run rc_events -- -max_len=8192
~~~

Run Miri on the portable state and memory code:

~~~text
cargo +nightly miri test -p rocev2-memory -p rocev2-core -p rocev2-wire --lib
cargo +nightly miri test -p rocev2 --no-default-features --lib connection::tests
~~~

Run the repository sanitizer workflow or equivalent nightly ASan/UBSan commands on Linux. Retain the exact nightly version and logs.

## 4. Linux RXE gate

Build both peers:

~~~text
bash interop/scripts/build-peers.sh
~~~

Run the complete clean-network matrix:

~~~text
sudo -E bash interop/scripts/rxe-matrix.sh
~~~

Run deterministic network fault profiles:

~~~text
sudo -E bash interop/scripts/rxe-fault-matrix.sh
~~~

Run the end-to-end benchmark matrix:

~~~text
ROCEV2_ITERATIONS=1000 sudo -E bash interop/scripts/rxe-benchmark.sh
~~~

The default matrix covers SEND, WRITE, and READ with either implementation as requester and starts PSNs near `0xfffff0` to cross the 24-bit rollover boundary.

## 5. Long reliability gate

Run the soak driver directly on a qualification host. Long soak runs should not depend on an interactive shell or a short CI step timeout.

~~~text
ROCEV2_SOAK_SECONDS=86400 sudo -E bash interop/scripts/rxe-soak.sh
ROCEV2_SOAK_SECONDS=172800 sudo -E bash interop/scripts/rxe-soak.sh
ROCEV2_SOAK_SECONDS=259200 sudo -E bash interop/scripts/rxe-soak.sh
~~~

Preserve every round directory. A failure must retain the first failing peer logs and environment data.

## 6. AF_XDP gate

The Rust peer supports the production AF_XDP backend through environment configuration.

~~~text
ROCEV2_BACKEND=afxdp
ROCEV2_IFINDEX=2
ROCEV2_QUEUE=0
ROCEV2_QUEUE_COUNT=1
ROCEV2_SOURCE_MAC=02:00:00:00:00:01
ROCEV2_DEST_MAC=02:00:00:00:00:02
~~~

By default AF_XDP qualification requires zero-copy mode. Set `ROCEV2_ALLOW_COPY_FALLBACK` only for an explicitly labeled copy/fallback test.

Qualify:

1. native XDP verifier and BPF-link attachment;
2. XSKMAP queue registration and cleanup;
3. RX/TX ring operation and NEED_WAKEUP behavior;
4. SEND, WRITE, and READ against a reference RNIC peer;
5. zero-copy mode reported by the socket;
6. repeated socket/QP/MR creation and teardown.

The current single-buffer backend must use a path MTU that fits one UMEM chunk. With the default 4096-byte chunk, do not qualify a 4096-byte RoCE path MTU.

## 7. Physical RNIC gate

Use `interop/rxe-peer/rxe-peer` against each supported hardware family. The peer uses standard libibverbs RC operations and contains no NIC-specific protocol implementation.

Record on both hosts:

~~~text
bash interop/scripts/capture-environment.sh <interface>
~~~

At minimum record NIC model, firmware, kernel, rdma-core, driver, GID, MTU, link rate, CPU affinity, NUMA node, and exact git commit. Capture representative known-good packets for SEND, WRITE, READ, retry, and rollover cases.

## 8. Scale, NUMA, and performance gate

Build the qualification driver in release mode:

~~~text
cargo build --locked --release --manifest-path tools/qualification/Cargo.toml
~~~

Run microbenchmarks:

~~~text
tools/qualification/target/release/rocev2-qualification micro 5000000
~~~

Validate the 100K-QP shard plan:

~~~text
tools/qualification/target/release/rocev2-qualification scale 128
~~~

Inspect queue/CPU/NUMA placement for the target interface:

~~~text
tools/qualification/target/release/rocev2-qualification placement eth0 8
~~~

Run end-to-end RXE and RNIC tests with fixed CPU affinity and NUMA placement. Collect throughput, operations/second, p50, p95, p99, p99.9, CPU utilization, cycles/packet, cycles/byte, cache references, cache misses, and allocation results.

The requester peers emit elapsed time, payload bytes, and latency percentiles as JSON lines so raw results remain machine-readable.

## 9. Release review

Before tagging 1.0:

- rerun all hosted CI on the exact release commit;
- verify every unsafe boundary against its documented ownership/range/lifetime assumptions;
- confirm network input does not reach a release-mode panic path;
- review public API and documentation against the supported scope;
- verify unsupported AF_XDP features are still rejected or documented;
- retain raw qualification artifacts rather than only summary percentages.

A release is qualified only after every required environment-specific gate above has evidence. Harness presence alone is not evidence.
