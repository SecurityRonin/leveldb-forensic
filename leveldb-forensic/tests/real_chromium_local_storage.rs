//! Tier-2 validation against a **real Chromium-authored** Local Storage store.
//!
//! Unlike `decode.rs` (constructed records + a `rusty-leveldb`-written oracle),
//! this test drives [`decode_local_storage`] over a `leveldb` directory produced
//! by a genuine Google Chrome browser running four known `localStorage.setItem`
//! writes. The bytes are real Chromium output; the ground truth is those four
//! documented writes (see `tests/data/README.md` for the mint procedure).
//!
//! This is the tier-1 follow-up called out in `docs/validation.md`: the decode
//! layer is confirmed against a Chromium profile, not only self-shaped records.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use leveldb_forensic::{decode_local_storage, Encoding, LocalStorageRecord};

/// The `leveldb` directory of the committed real-Chromium fixture. The repo root
/// is one level above this crate's manifest dir (workspace member layout).
fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tests/data/chromium-local-storage/leveldb")
}

/// The origin every write was made under (the local mint server).
const ORIGIN: &str = "http://127.0.0.1:8117";

/// Find the live (non-deleted) Data value for `script_key` under [`ORIGIN`].
fn data_value(recs: &[LocalStorageRecord], script_key: &str) -> Option<(String, Encoding, bool)> {
    recs.iter().find_map(|r| match r {
        LocalStorageRecord::Data {
            origin,
            script_key: k,
            value,
            deleted: false,
            ..
        } if origin == ORIGIN && k.text == script_key => {
            Some((value.text.clone(), value.encoding, value.lossy))
        }
        _ => None,
    })
}

#[test]
fn decodes_known_writes_from_real_chromium_store() {
    let recs = decode_local_storage(&fixture_dir())
        .expect("read + decode the committed real-Chromium Local Storage fixture");

    // Ground truth: the four localStorage.setItem writes the mint page ran.
    // ASCII values fit Latin-1, so Chromium stores them type-prefixed 0x01.
    assert_eq!(
        data_value(&recs, "case_id"),
        Some(("CASE-001".to_string(), Encoding::Latin1, false)),
        "case_id"
    );
    assert_eq!(
        data_value(&recs, "greeting"),
        Some(("Hello, forensics!".to_string(), Encoding::Latin1, false)),
        "greeting"
    );
    assert_eq!(
        data_value(&recs, "count"),
        Some(("42".to_string(), Encoding::Latin1, false)),
        "count"
    );
    // A value with non-Latin-1 code points forces Chromium's UTF-16-LE encoding
    // (type prefix 0x00) — exercises the other decode path on real bytes.
    assert_eq!(
        data_value(&recs, "unicode"),
        Some(("日本語 café ☕".to_string(), Encoding::Utf16Le, false)),
        "unicode"
    );
}

#[test]
fn surfaces_origin_metadata_from_real_chromium_store() {
    let recs = decode_local_storage(&fixture_dir()).expect("read + decode fixture");

    // Chromium writes a `META:` record per origin carrying a last-modified
    // timestamp (WebKit microseconds) and a declared size. We do not hard-code
    // the exact timestamp (it is the real wall-clock of the mint) — we assert it
    // is present, plausible (post-2020), and attributed to our origin.
    let meta = recs
        .iter()
        .find_map(|r| match r {
            LocalStorageRecord::Meta {
                origin,
                timestamp_webkit_micros,
                size,
                deleted: false,
                ..
            } if origin == ORIGIN => Some((*timestamp_webkit_micros, *size)),
            _ => None,
        })
        .expect("a META record for the mint origin");

    // WebKit epoch is 1601-01-01; ~1.32e16 µs is ~2020. A real mint timestamp is
    // far above that floor and below a 2100 ceiling.
    assert!(
        meta.0 > 13_200_000_000_000_000 && meta.0 < 16_000_000_000_000_000,
        "META timestamp {} outside plausible range",
        meta.0
    );
    assert!(meta.1.is_some(), "META should carry a declared size");
}
