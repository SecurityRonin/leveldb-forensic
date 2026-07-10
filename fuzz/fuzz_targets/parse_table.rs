//! Fuzz the SSTable reader on arbitrary bytes.
//!
//! `parse_table_bytes` walks the footer (magic + block handles), the index
//! block, and every data block (prefix-compressed entries, restart array,
//! masked crc32c, optional Snappy). On crafted / corrupted / truncated input it
//! must return `Ok` or a typed `Err` — never panic, abort, or over-allocate.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::path::Path;

fuzz_target!(|data: &[u8]| {
    let _ = leveldb_core::parse_table_bytes(data, Path::new("fuzz.ldb"));
});
