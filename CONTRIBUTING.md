# Contributing

All protocol changes must include:

1. a citation to the relevant IBTA/IEEE/IETF/IANA specification or Linux/RDMA reference behavior;
2. unit tests containing both accepted and rejected packets;
3. a no-allocation argument for the steady-state path;
4. fuzz or property coverage for new parsing/state-machine code; and
5. an interoperability note when behavior can differ from Linux RXE or hardware RNICs.

Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`,
`cargo test --workspace --all-features`, and `cargo test -p rocev2-wire --no-default-features` before
submitting.
