//! End-to-end CLI tests: write a real LevelDB with the `rusty-leveldb` oracle,
//! then run the CLI over it and assert on the rendered output.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default
)]

use std::path::Path;

use leveldb4n6::{run, Format, Mode};

fn write_db(dir: &Path, entries: &[(&[u8], Option<&[u8]>)]) {
    let mut o = rusty_leveldb::Options::default();
    o.create_if_missing = true;
    o.reuse_logs = false;
    let mut db = rusty_leveldb::DB::open(dir, o).unwrap();
    for (k, v) in entries {
        match v {
            Some(val) => db.put(k, val).unwrap(),
            None => db.delete(k).unwrap(),
        }
    }
    db.flush().unwrap();
}

fn utf16(s: &str) -> Vec<u8> {
    let mut out = vec![0u8];
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

fn run_to_string(dir: &Path, mode: Mode, format: Format) -> String {
    let mut buf: Vec<u8> = Vec::new();
    run(dir, mode, format, &mut buf).unwrap();
    String::from_utf8(buf).unwrap()
}

#[test]
fn raw_text_shows_hex_seq_and_tombstone() {
    let tmp = tempfile::tempdir().unwrap();
    write_db(
        tmp.path(),
        &[
            (b"hello", Some(b"world")),
            (b"gone", Some(b"x")),
            (b"gone", None),
        ],
    );

    let out = run_to_string(tmp.path(), Mode::Raw, Format::Text);
    // "hello" = 68656c6c6f, "world" = 776f726c64
    assert!(out.contains("68656c6c6f"), "key hex missing:\n{out}");
    assert!(out.contains("776f726c64"), "value hex missing:\n{out}");
    assert!(out.contains("seq="), "seq label missing:\n{out}");
    assert!(out.contains("deleted=true"), "tombstone not shown:\n{out}");
}

#[test]
fn raw_jsonl_is_one_object_per_line() {
    let tmp = tempfile::tempdir().unwrap();
    write_db(tmp.path(), &[(b"a", Some(b"b"))]);
    let out = run_to_string(tmp.path(), Mode::Raw, Format::Jsonl);
    let line = out
        .lines()
        .find(|l| l.contains("key_hex"))
        .expect("a jsonl record line");
    assert!(line.trim_start().starts_with('{') && line.trim_end().ends_with('}'));
    assert!(line.contains("\"key_hex\":\"61\""), "hex key field:\n{out}");
    assert!(line.contains("\"deleted\":false"));
}

#[test]
fn raw_csv_has_header() {
    let tmp = tempfile::tempdir().unwrap();
    write_db(tmp.path(), &[(b"a", Some(b"b"))]);
    let out = run_to_string(tmp.path(), Mode::Raw, Format::Csv);
    assert!(
        out.lines().next().unwrap().contains("key_hex"),
        "csv header:\n{out}"
    );
    assert!(out.contains(",61,"), "hex key cell:\n{out}"); // 'a' = 0x61
}

#[test]
fn local_text_decodes_value() {
    let tmp = tempfile::tempdir().unwrap();
    let mut key = vec![b'_'];
    key.extend_from_slice(b"https://app.example");
    key.push(0);
    key.extend_from_slice(&utf16("theme"));
    write_db(tmp.path(), &[(&key, Some(&utf16("dark")))]);

    let out = run_to_string(tmp.path(), Mode::Local, Format::Text);
    assert!(out.contains("theme"), "script key missing:\n{out}");
    assert!(out.contains("dark"), "decoded value missing:\n{out}");
    assert!(
        out.contains("https://app.example"),
        "origin missing:\n{out}"
    );
}

#[test]
fn session_jsonl_decodes_and_joins_host() {
    let tmp = tempfile::tempdir().unwrap();
    let ns = b"namespace-abc123-https://s.example".to_vec();
    let map = b"map-7-greeting".to_vec();
    write_db(tmp.path(), &[(&ns, Some(b"7")), (&map, Some(&utf16("hi")))]);

    let out = run_to_string(tmp.path(), Mode::Session, Format::Jsonl);
    assert!(out.contains("greeting"), "map script key missing:\n{out}");
    assert!(out.contains("hi"), "decoded value missing:\n{out}");
    assert!(
        out.contains("https://s.example"),
        "host join missing:\n{out}"
    );
}

#[test]
fn missing_directory_is_a_loud_error() {
    let mut buf: Vec<u8> = Vec::new();
    let err = run(
        Path::new("/no/such/leveldb/dir"),
        Mode::Raw,
        Format::Text,
        &mut buf,
    );
    assert!(
        err.is_err(),
        "a missing directory must error, not silently produce nothing"
    );
}
