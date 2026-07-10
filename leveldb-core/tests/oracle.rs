//! Independent-oracle validation (Doer-Checker, Evidence-Based Rigor tier 2).
//!
//! We do NOT hand-encode LevelDB bytes and assert our own reader agrees with
//! them (the self-fixture trap). Instead the pure-Rust `rusty-leveldb`
//! reimplementation WRITES real `.ldb`/`.log` files with known overwrites and
//! deletes; our reader then reads them back and confirms:
//!   (a) every live key's latest value matches what `rusty-leveldb` returns, and
//!   (b) the superseded and deleted records — which `rusty-leveldb`'s merged
//!       `get()` view HIDES — also surface.
//!
//! Ground truth is derivable from the documented construction: we chose the
//! writes, and `rusty-leveldb` is an independent implementation of the writer.

use std::collections::BTreeMap;
use std::path::Path;

use rusty_leveldb::{Options, DB};

/// Build a disk-backed DB with a tiny write buffer so the memtable spills to
/// real L0 `.ldb` SSTables (preserving every version), leaving the current
/// memtable in the `.log`. No compaction is triggered — compaction to the
/// bottom level would drop the tombstones/old versions that are the payload.
fn disk_opts(compressor: u8) -> Options {
    let mut o = Options::default();
    o.create_if_missing = true;
    o.write_buffer_size = 256; // force frequent memtable -> SSTable flushes
    o.reuse_logs = false;
    o.reuse_manifest = false;
    o.compressor = compressor;
    o
}

fn extensions_present(dir: &Path) -> (bool, bool) {
    let (mut ldb, mut log) = (false, false);
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        match p.extension().and_then(|s| s.to_str()) {
            Some("ldb") => ldb = true,
            Some("log") => log = true,
            _ => {}
        }
    }
    (ldb, log)
}

/// Collect our reader's records keyed by (user key) -> list of (value, seq,
/// deleted), so we can assert on every version, not just the merged latest.
fn read_all(dir: &Path) -> Vec<leveldb_core::Record> {
    leveldb_core::read_dir(dir).expect("read_dir on a valid leveldb directory")
}

#[test]
fn live_deleted_and_superseded_all_surface() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    // ---- write phase (the oracle authors the files) ----
    let live_expected: BTreeMap<Vec<u8>, Vec<u8>> = {
        let mut db = DB::open(dir, disk_opts(0)).unwrap();

        // Bulk keys to force multiple memtable flushes into .ldb files.
        for i in 0..40u32 {
            let k = format!("key{i:03}");
            let v = format!("value-{i:03}");
            db.put(k.as_bytes(), v.as_bytes()).unwrap();
        }

        // Overwrite one key (creates a superseded version) ...
        db.put(b"key007", b"ORIGINAL").unwrap();
        db.put(b"key007", b"UPDATED").unwrap();

        // ... and delete another (creates a tombstone).
        db.delete(b"key013").unwrap();

        db.flush().unwrap();

        // Ground-truth live view straight from the oracle's own merged reader.
        let mut expected = BTreeMap::new();
        for i in 0..40u32 {
            if i == 13 {
                continue; // deleted
            }
            let k = format!("key{i:03}");
            let got = db
                .get(k.as_bytes())
                .expect("live key present in oracle view");
            expected.insert(k.into_bytes(), got.to_vec());
        }
        expected
    };

    // Prove both on-disk structures were exercised.
    let (has_ldb, has_log) = extensions_present(dir);
    assert!(
        has_ldb,
        "oracle should have produced at least one .ldb SSTable"
    );
    assert!(has_log, "oracle should have left a .log write-ahead log");

    // ---- read phase (our reader) ----
    let recs = read_all(dir);
    assert!(!recs.is_empty(), "reader surfaced no records");

    // (a) Every live key's LATEST (max-seq, non-deleted) value matches the oracle.
    for (k, want) in &live_expected {
        let latest = recs
            .iter()
            .filter(|r| &r.key == k && !r.deleted)
            .max_by_key(|r| r.seq)
            .unwrap_or_else(|| panic!("no live record for {k:?}"));
        assert_eq!(&latest.value, want, "latest value mismatch for {k:?}");
    }

    // (b1) The deletion tombstone for key013 surfaces — hidden by a merged view.
    assert!(
        recs.iter().any(|r| r.key == b"key013" && r.deleted),
        "deletion tombstone for key013 did not surface"
    );

    // (b2) The superseded ORIGINAL value of key007 surfaces alongside UPDATED.
    let mut k7: Vec<&leveldb_core::Record> = recs
        .iter()
        .filter(|r| r.key == b"key007" && !r.deleted)
        .collect();
    k7.sort_by_key(|r| r.seq);
    assert!(
        k7.iter().any(|r| r.value == b"UPDATED"),
        "current value of key007 missing"
    );
    assert!(
        k7.iter().any(|r| r.value == b"ORIGINAL"),
        "superseded value of key007 did not surface (the forensic payload)"
    );
    assert!(
        k7.len() >= 2,
        "expected >=2 versions of key007, got {}",
        k7.len()
    );

    // Sequence numbers are monotonic with write order: UPDATED > ORIGINAL.
    let orig_seq = k7
        .iter()
        .find(|r| r.value == b"ORIGINAL")
        .map(|r| r.seq)
        .unwrap();
    let upd_seq = k7
        .iter()
        .find(|r| r.value == b"UPDATED")
        .map(|r| r.seq)
        .unwrap();
    assert!(
        upd_seq > orig_seq,
        "seq ordering wrong: {upd_seq} !> {orig_seq}"
    );
}

#[test]
fn snappy_compressed_blocks_decode() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    // A long, highly compressible value so the SSTable block builder actually
    // stores it Snappy-compressed (compression type 1), exercising our decode.
    let big = vec![b'A'; 8192];
    {
        let mut db = DB::open(dir, disk_opts(1)).unwrap();
        for i in 0..20u32 {
            db.put(format!("z{i:03}").as_bytes(), &big).unwrap();
        }
        db.flush().unwrap();
    }
    assert!(
        extensions_present(dir).0,
        "expected a .ldb with a compressed block"
    );

    let recs = read_all(dir);
    assert!(
        recs.iter().any(|r| r.value == big && !r.deleted),
        "did not recover the compressible value through the Snappy path"
    );
}
