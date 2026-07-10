//! Fuzz the Session Storage decoder on an arbitrary record.
//!
//! Exercises `namespace-` / `map-` key splitting, the map-id/host join, and the
//! defensive UTF-16-LE value decode. Must never panic on hostile key/value bytes.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::path::PathBuf;

use leveldb_core::Record;

fuzz_target!(|input: (Vec<u8>, Vec<u8>, u64, bool)| {
    let (key, value, seq, deleted) = input;
    let rec = Record {
        key,
        value,
        seq,
        deleted,
        origin_file: PathBuf::from("fuzz"),
    };
    let _ = leveldb_forensic::decode_session_storage_records(&[rec]);
});
