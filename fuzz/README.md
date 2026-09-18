# Bounded safety fuzzing

The four targets execute only local in-memory code. Inputs cannot select a network
peer or cause Linux syscalls. Each event stream has a 256-event budget. MR tests
retain guard bytes and a reference model; RC tests track completion identity,
queue capacity, stale handles, reset/error, ACK/NAK/RNR, timeout and malformed input.
Wire tests compare CRC against an independent bitwise implementation and check all
18 wire opcodes, including padding and immediate-data codec variants (not a claim
that the transport executor implements immediate operations).

```sh
cargo install cargo-fuzz --locked
cargo +nightly fuzz run wire_decode -- -max_len=8192 -max_total_time=300
cargo +nightly fuzz run wire_roundtrip -- -max_len=4120 -max_total_time=300
cargo +nightly fuzz run memory_registry -- -max_len=1024 -max_total_time=300
cargo +nightly fuzz run rc_events -- -max_len=4096 -max_total_time=300
cargo +nightly fuzz tmin rc_events artifacts/rc_events/crash-EXACT_HASH
cargo +nightly fuzz run rc_events artifacts/rc_events/crash-EXACT_HASH
cargo test --manifest-path fuzz/Cargo.toml --lib
```

Archive the corpus, minimized artifacts, exact source SHA, `rustc -Vv`, elapsed
campaign time and libFuzzer statistics. A smoke run is not sustained qualification.
The native allocation counter is separate from sanitizer/Miri instrumentation.

Sources: https://rust-fuzz.github.io/book/cargo-fuzz/tutorial.html and
https://github.com/rust-lang/miri .
