//! Local/Session Storage decode tests.
//!
//! The decode logic is exercised two ways:
//!  * directly on constructed [`Record`]s whose Chrome-shaped key/value bytes are
//!    built per the documented ccl_chromium_reader format (the ground truth is
//!    the format definition), and
//!  * end-to-end through a real LevelDB written by the `rusty-leveldb` oracle,
//!    proving the whole `read_dir` -> decode pipeline (the LevelDB layer is
//!    oracle-backed; the decoded string's ground truth is derivable from how the
//!    value was encoded).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default
)]

use std::path::PathBuf;

use leveldb_core::Record;
use leveldb_forensic::{
    decode_local_storage, decode_local_storage_records, decode_session_storage,
    decode_session_storage_records, Encoding, LocalStorageRecord, SessionStorageRecord,
};

fn rec(key: Vec<u8>, value: Vec<u8>, seq: u64, deleted: bool) -> Record {
    Record {
        key,
        value,
        seq,
        deleted,
        origin_file: PathBuf::from("000005.log"),
    }
}

/// A type-prefixed UTF-16-LE string: `0x00` + UTF-16-LE bytes.
fn utf16_value(s: &str) -> Vec<u8> {
    let mut out = vec![0x00u8];
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

/// A type-prefixed Latin-1 string: `0x01` + one byte per code point.
fn latin1_value(s: &str) -> Vec<u8> {
    let mut out = vec![0x01u8];
    out.extend(s.chars().map(|c| c as u8));
    out
}

/// `_` + origin + `0x00` + type-prefixed script key.
fn ls_data_key(origin: &str, script_key_prefixed: &[u8]) -> Vec<u8> {
    let mut out = vec![b'_'];
    out.extend_from_slice(origin.as_bytes());
    out.push(0x00);
    out.extend_from_slice(script_key_prefixed);
    out
}

fn leb128(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
    out
}

#[test]
fn local_storage_data_utf16_and_latin1() {
    let recs = vec![
        rec(
            ls_data_key("https://mail.example.com", &utf16_value("theme")),
            utf16_value("dark"),
            10,
            false,
        ),
        rec(
            ls_data_key("https://mail.example.com", &latin1_value("count")),
            latin1_value("5"),
            11,
            false,
        ),
    ];
    let decoded = decode_local_storage_records(&recs);

    let dark = decoded
        .iter()
        .find_map(|r| match r {
            LocalStorageRecord::Data {
                origin,
                script_key,
                value,
                seq,
                deleted,
            } if script_key.text == "theme" => {
                Some((origin.clone(), value.clone(), *seq, *deleted))
            }
            _ => None,
        })
        .expect("theme record decoded");
    assert_eq!(dark.0, "https://mail.example.com");
    assert_eq!(dark.1.text, "dark");
    assert_eq!(dark.1.encoding, Encoding::Utf16Le);
    assert!(!dark.1.lossy);
    assert_eq!(dark.2, 10);
    assert!(!dark.3);

    let count = decoded
        .iter()
        .find_map(|r| match r {
            LocalStorageRecord::Data {
                script_key, value, ..
            } if script_key.text == "count" => Some(value.clone()),
            _ => None,
        })
        .expect("count record decoded");
    assert_eq!(count.text, "5");
    assert_eq!(count.encoding, Encoding::Latin1);
    assert!(!count.lossy);
}

#[test]
fn local_storage_deletion_tombstone_surfaces() {
    let recs = vec![rec(
        ls_data_key("https://x.example", &utf16_value("token")),
        Vec::new(),
        20,
        true,
    )];
    let decoded = decode_local_storage_records(&recs);
    assert!(
        decoded.iter().any(|r| matches!(
            r,
            LocalStorageRecord::Data { deleted: true, script_key, .. } if script_key.text == "token"
        )),
        "deleted Local Storage key should surface as a tombstone"
    );
}

#[test]
fn local_storage_lone_surrogate_is_lossy_not_a_panic() {
    // A lone high surrogate (0xD800) with no low surrogate — real sites store
    // these. Decoding must flag lossy and preserve the raw bytes, never crash.
    let mut val = vec![0x00u8];
    val.extend_from_slice(&0xD800u16.to_le_bytes());
    let recs = vec![rec(
        ls_data_key("https://y.example", &utf16_value("k")),
        val.clone(),
        30,
        false,
    )];
    let decoded = decode_local_storage_records(&recs);
    let v = decoded
        .iter()
        .find_map(|r| match r {
            LocalStorageRecord::Data { value, .. } => Some(value.clone()),
            _ => None,
        })
        .expect("record present");
    assert!(v.lossy, "lone surrogate must set the lossy flag");
    assert_eq!(v.raw, val, "raw bytes preserved for the caller");
    assert!(v.text.contains('\u{FFFD}'));
}

#[test]
fn local_storage_meta_and_other() {
    let origin = "https://meta.example";
    let mut meta_key = b"META:".to_vec();
    meta_key.extend_from_slice(origin.as_bytes());
    let mut meta_val = vec![0x08u8]; // field 1, varint
    meta_val.extend(leb128(13_350_000_000_000_000));
    meta_val.push(0x10); // field 2, varint
    meta_val.extend(leb128(4096));

    let recs = vec![
        rec(meta_key, meta_val, 5, false),
        rec(b"VERSION".to_vec(), vec![1], 1, false),
    ];
    let decoded = decode_local_storage_records(&recs);

    let meta = decoded
        .iter()
        .find_map(|r| match r {
            LocalStorageRecord::Meta {
                origin,
                timestamp_webkit_micros,
                size,
                ..
            } => Some((origin.clone(), *timestamp_webkit_micros, *size)),
            _ => None,
        })
        .expect("META decoded");
    assert_eq!(meta.0, origin);
    assert_eq!(meta.1, 13_350_000_000_000_000);
    assert_eq!(meta.2, Some(4096));

    assert!(
        decoded
            .iter()
            .any(|r| matches!(r, LocalStorageRecord::Other { key, .. } if key == b"VERSION")),
        "VERSION key should surface as Other with raw bytes"
    );
}

#[test]
fn session_storage_namespace_and_map_join() {
    let guid = "d34db33f0000";
    let host = "https://sess.example.com";
    let ns_key = format!("namespace-{guid}-{host}");
    let map_key = "map-42-greeting";

    let recs = vec![
        rec(ns_key.into_bytes(), b"42".to_vec(), 3, false),
        rec(map_key.as_bytes().to_vec(), utf16_value("hello"), 4, false),
    ];
    let decoded = decode_session_storage_records(&recs);

    let ns = decoded
        .iter()
        .find_map(|r| match r {
            SessionStorageRecord::Namespace {
                guid, host, map_id, ..
            } => Some((guid.clone(), host.clone(), map_id.clone())),
            _ => None,
        })
        .expect("namespace decoded");
    assert_eq!(ns.0, guid);
    assert_eq!(ns.1, host);
    assert_eq!(ns.2, "42");

    let map = decoded
        .iter()
        .find_map(|r| match r {
            SessionStorageRecord::Map {
                map_id,
                host,
                script_key,
                value,
                ..
            } => Some((
                map_id.clone(),
                host.clone(),
                script_key.clone(),
                value.clone(),
            )),
            _ => None,
        })
        .expect("map decoded");
    assert_eq!(map.0, "42");
    assert_eq!(
        map.1,
        Some(host.to_string()),
        "map entry joined to its host via map-id"
    );
    assert_eq!(map.2, "greeting");
    assert_eq!(map.3.text, "hello");
}

#[test]
fn session_storage_other_key_surfaces_raw() {
    // A key matching neither the namespace- nor map- shape must surface as
    // Other with its raw bytes, not be dropped.
    let recs = vec![rec(b"version".to_vec(), b"1".to_vec(), 9, false)];
    let decoded = decode_session_storage_records(&recs);
    assert!(
        decoded
            .iter()
            .any(|r| matches!(r, SessionStorageRecord::Other { key, .. } if key == b"version")),
        "an unrecognised session key should surface as Other"
    );
}

fn write_oracle_db(dir: &std::path::Path, entries: &[(Vec<u8>, Vec<u8>)]) {
    let mut o = rusty_leveldb::Options::default();
    o.create_if_missing = true;
    o.reuse_logs = false;
    let mut db = rusty_leveldb::DB::open(dir, o).unwrap();
    for (k, v) in entries {
        db.put(k, v).unwrap();
    }
    db.flush().unwrap();
}

#[test]
fn decode_local_storage_reads_a_directory() {
    // Exercise the directory-reading convenience wrapper end to end.
    let tmp = tempfile::tempdir().unwrap();
    write_oracle_db(
        tmp.path(),
        &[(
            ls_data_key("https://dir.example", &utf16_value("k")),
            utf16_value("v"),
        )],
    );
    let decoded = decode_local_storage(tmp.path()).unwrap();
    assert!(
        decoded.iter().any(|r| matches!(
            r,
            LocalStorageRecord::Data { script_key, value, .. }
                if script_key.text == "k" && value.text == "v"
        )),
        "decode_local_storage should read + decode the directory"
    );
}

#[test]
fn decode_session_storage_reads_a_directory() {
    let tmp = tempfile::tempdir().unwrap();
    write_oracle_db(
        tmp.path(),
        &[
            (
                b"namespace-guid-https://dir.example".to_vec(),
                b"7".to_vec(),
            ),
            (b"map-7-hello".to_vec(), utf16_value("world")),
        ],
    );
    let decoded = decode_session_storage(tmp.path()).unwrap();
    assert!(
        decoded.iter().any(|r| matches!(
            r,
            SessionStorageRecord::Map { script_key, value, host: Some(h), .. }
                if script_key == "hello" && value.text == "world" && h == "https://dir.example"
        )),
        "decode_session_storage should read + decode + host-join the directory"
    );
}

#[test]
fn end_to_end_local_storage_via_oracle() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    {
        let mut o = rusty_leveldb::Options::default();
        o.create_if_missing = true;
        o.reuse_logs = false;
        let mut db = rusty_leveldb::DB::open(dir, o).unwrap();
        db.put(
            &ls_data_key("https://app.example", &utf16_value("session")),
            &utf16_value("abc123"),
        )
        .unwrap();
        db.put(
            &ls_data_key("https://app.example", &utf16_value("temp")),
            &utf16_value("x"),
        )
        .unwrap();
        db.delete(&ls_data_key("https://app.example", &utf16_value("temp")))
            .unwrap();
        db.flush().unwrap();
    }

    let recs = leveldb_core::read_dir(dir).unwrap();
    let decoded = decode_local_storage_records(&recs);

    assert!(
        decoded.iter().any(|r| matches!(
            r,
            LocalStorageRecord::Data { script_key, value, deleted: false, .. }
                if script_key.text == "session" && value.text == "abc123"
        )),
        "live value did not round-trip through the full pipeline"
    );
    assert!(
        decoded.iter().any(|r| matches!(
            r,
            LocalStorageRecord::Data { script_key, deleted: true, .. } if script_key.text == "temp"
        )),
        "deleted key tombstone did not surface end-to-end"
    );
}
