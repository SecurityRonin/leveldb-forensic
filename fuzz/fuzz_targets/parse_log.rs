//! Fuzz the write-ahead log reader on arbitrary bytes.
//!
//! `parse_log_bytes` walks 32 KiB blocks, physical-record headers (crc / length
//! / type), fragment reassembly, and `WriteBatch` ops. On any input it must
//! return without panicking, aborting, or over-allocating.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::path::Path;

fuzz_target!(|data: &[u8]| {
    let _ = leveldb_core::parse_log_bytes(data, Path::new("fuzz.log"));
});
