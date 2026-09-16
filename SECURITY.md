# Security policy

`rocev2-rs` processes unauthenticated network input and can modify registered memory. Treat every
parser and bounds-checking defect as security-sensitive.

Please report suspected vulnerabilities privately through GitHub Security Advisories. Do not open a
public issue until maintainers have assessed the report.

The default branch is pre-1.0 software. It is not yet approved for production data paths. The unsafe
surface is restricted to the Linux I/O bindings and the checked memory-copy boundary; CI rejects
unsafe code in all other crates.
