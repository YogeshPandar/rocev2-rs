# Qualification drivers

These hosted tools are intentionally outside the production workspace. They
exercise data structures and Linux placement helpers without adding `std` or
benchmark dependencies to the transport crates.

Build with Rust 1.85 or newer:

```text
cargo build --release --manifest-path tools/qualification/Cargo.toml
```

Run portable microbenchmarks:

```text
target/release/rocev2-qualification micro 5000000
```

Validate the 100K-QP shard plan:

```text
target/release/rocev2-qualification scale 128
```

Inspect queue, CPU, and NUMA placement for a Linux interface:

```text
target/release/rocev2-qualification placement eth0 8
```

Record the exact commit, CPU, kernel, NIC, affinity, NUMA node, MTU, and raw
JSON output for every qualification run. The drivers do not imply a performance
result until executed on the target system.
