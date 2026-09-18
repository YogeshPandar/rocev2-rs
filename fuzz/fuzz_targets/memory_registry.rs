#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| rocev2_fuzz::memory_registry(data));
