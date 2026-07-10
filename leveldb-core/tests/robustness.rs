//! Adversarial / robustness tests (Evidence-Based Rigor tier 3).
//!
//! These are the edge cases real corpora lack — truncation, bad magic, lying
//! lengths, oversized counts, corrupt crc. The invariant under test is a
//! *property*, not a value: the parser must return `Err` (or an empty result),
//! and must NEVER panic, abort, or over-allocate. The value-producing
//! correctness of the reader is oracle-checked separately (see `oracle.rs`);
//! the runtime backstop for these is the `cargo-fuzz` targets.

use std::path::Path;

use leveldb_core::{parse_log_bytes, parse_table_bytes};

fn origin() -> &'static Path {
    Path::new("test.ldb")
}

const TABLE_MAGIC_LE: [u8; 8] = [0x57, 0xfb, 0x80, 0x8b, 0x24, 0x75, 0x47, 0xdb];

#[test]
fn table_empty_input_errors_not_panics() {
    assert!(parse_table_bytes(&[], origin()).is_err());
}

#[test]
fn table_shorter_than_footer_errors() {
    assert!(parse_table_bytes(&[0u8; 10], origin()).is_err());
}

#[test]
fn table_bad_magic_errors() {
    // 48-byte footer with the WRONG magic in the last 8 bytes.
    let mut buf = vec![0u8; 48];
    buf[40..48].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00]);
    assert!(parse_table_bytes(&buf, origin()).is_err());
}

#[test]
fn table_good_magic_but_garbage_handles_errors() {
    // Correct magic, but the block handles point past the tiny buffer.
    let mut buf = vec![0u8; 48];
    // metaindex handle offset=0xff.. size=0xff.. (varints), index handle likewise.
    buf[0] = 0xff;
    buf[1] = 0xff;
    buf[2] = 0x7f;
    buf[40..48].copy_from_slice(&TABLE_MAGIC_LE);
    let r = parse_table_bytes(&buf, origin());
    assert!(
        r.is_err(),
        "handles pointing past EOF must error, got {r:?}"
    );
}

#[test]
fn table_arbitrary_bytes_never_panic() {
    // A spread of hostile inputs — the point is "no panic", any Result is fine.
    for len in [0usize, 1, 5, 47, 48, 49, 64, 100, 4096] {
        let buf: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
        let _ = parse_table_bytes(&buf, origin());
        // Same bytes with a valid trailing magic.
        let mut with_magic = buf.clone();
        if with_magic.len() >= 48 {
            let n = with_magic.len();
            with_magic[n - 8..].copy_from_slice(&TABLE_MAGIC_LE);
        }
        let _ = parse_table_bytes(&with_magic, origin());
    }
}

#[test]
fn log_empty_input_is_ok_empty() {
    // An empty log is legitimately zero records, not an error.
    let recs = parse_log_bytes(&[], Path::new("x.log")).unwrap();
    assert!(recs.is_empty());
}

#[test]
fn log_truncated_header_never_panics() {
    for len in 0..7usize {
        let buf = vec![0xa5u8; len];
        let _ = parse_log_bytes(&buf, Path::new("x.log"));
    }
}

#[test]
fn log_lying_length_never_panics() {
    // 7-byte header claiming a 60000-byte payload that isn't there.
    let mut buf = vec![0u8; 7];
    buf[4] = 0x60; // length low byte
    buf[5] = 0xea; // length high byte -> ~60000
    buf[6] = 1; // FULL
    let recs = parse_log_bytes(&buf, Path::new("x.log")).unwrap();
    assert!(
        recs.is_empty(),
        "a lying length should yield no records, not a panic"
    );
}

#[test]
fn log_arbitrary_bytes_never_panic() {
    for len in [1usize, 7, 8, 100, 32 * 1024, 32 * 1024 + 9, 70_000] {
        let buf: Vec<u8> = (0..len).map(|i| (i * 31 + 5) as u8).collect();
        let _ = parse_log_bytes(&buf, Path::new("x.log"));
    }
}
