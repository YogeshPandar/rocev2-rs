//! Reproducible portable CRC throughput smoke benchmark.
use rocev2_wire::Icrc;
use std::hint::black_box;
use std::time::Instant;

fn main() {
    if cfg!(debug_assertions) {
        return;
    }
    let bytes = [0xa5_u8; 4096];
    for length in [64, 256, 1024, 1500, 4096] {
        let iterations = 100_000_u32;
        let start = Instant::now();
        for _ in 0..iterations {
            let mut crc = Icrc::new();
            crc.update(black_box(&bytes[..length]));
            black_box(crc.finalize());
        }
        println!(
            "icrc bytes={length} iterations={iterations} elapsed_ns={}",
            start.elapsed().as_nanos()
        );
    }
}
