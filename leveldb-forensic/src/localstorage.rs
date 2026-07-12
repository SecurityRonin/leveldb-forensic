//! Chrome/Chromium Local Storage record types.
//!
//! Reference: `cclgroupltd/ccl_chromium_reader` `ccl_chromium_localstorage.py`.
//! A `Local Storage/leveldb` directory holds three key shapes:
//! * `META:` + storage_key → a small protobuf (`0x08` timestamp varint,
//!   `0x10` size varint) — origin-level metadata.
//! * `_` + storage_key + `0x00` + script_key → a type-prefixed value string.
//! * `VERSION` and other bookkeeping keys.

use crate::value::{decode_type_prefixed, StorageValue};
use leveldb_core::Record;
use protobuf_forensic_core::FieldValue;

const META_PREFIX: &[u8] = b"META:";

/// One decoded Local Storage record. Deletion tombstones and superseded versions
/// surface too (each carries its `seq` and `deleted` flag).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalStorageRecord {
    /// Origin-level metadata from a `META:` key.
    Meta {
        /// The storage key (origin) this metadata describes.
        origin: String,
        /// Last-modified time, WebKit microseconds (µs since 1601-01-01 UTC).
        timestamp_webkit_micros: u64,
        /// Declared size in bytes, if the protobuf carried the size field.
        size: Option<u64>,
        /// LevelDB sequence number.
        seq: u64,
        /// `true` if this is a deletion tombstone.
        deleted: bool,
    },
    /// An actual stored key/value pair.
    Data {
        /// The storage key (origin), decoded as Latin-1.
        origin: String,
        /// The script-visible key (a type-prefixed string).
        script_key: StorageValue,
        /// The stored value (a type-prefixed string; empty for a tombstone).
        value: StorageValue,
        /// LevelDB sequence number.
        seq: u64,
        /// `true` if this is a deletion tombstone.
        deleted: bool,
    },
    /// A key that did not match the Meta or Data shapes (e.g. `VERSION`). The raw
    /// key bytes are surfaced verbatim rather than dropped.
    Other {
        /// The raw user key.
        key: Vec<u8>,
        /// LevelDB sequence number.
        seq: u64,
        /// `true` if this is a deletion tombstone.
        deleted: bool,
    },
}

/// Decode a byte string as `iso-8859-1` (Latin-1): each byte is one code point.
fn latin1(raw: &[u8]) -> String {
    raw.iter().map(|&b| b as char).collect()
}

/// Parse the `StorageMetadata` protobuf: field 1 is the WebKit-µs timestamp
/// varint; optional field 2 is the size varint. Returns `None` unless the payload
/// is a well-formed protobuf whose first field is the field-1 timestamp varint.
fn parse_meta_protobuf(data: &[u8]) -> Option<(u64, Option<u64>)> {
    let fields = protobuf_forensic_core::decode(data).ok()?;
    // Field 1 (the timestamp) must be present and first, as Chrome writes it.
    let timestamp = match fields.first()? {
        f if f.number == 1 => match f.value {
            FieldValue::Varint(v) => v,
            _ => return None,
        },
        _ => return None,
    };
    // Optional field 2 (the declared size), when it is the immediately-following
    // varint — matching the original single-pass reader.
    let size = match fields.get(1) {
        Some(f) if f.number == 2 => match f.value {
            FieldValue::Varint(v) => Some(v),
            _ => None,
        },
        _ => None,
    };
    Some((timestamp, size))
}

/// Decode Local Storage records from raw LevelDB records. Every record is
/// classified into [`LocalStorageRecord::Meta`], [`LocalStorageRecord::Data`],
/// or [`LocalStorageRecord::Other`]; deletion tombstones and superseded versions
/// are kept.
pub(crate) fn decode(records: &[Record]) -> Vec<LocalStorageRecord> {
    let mut out = Vec::with_capacity(records.len());
    for r in records {
        if let Some(storage_key_raw) = r.key.strip_prefix(META_PREFIX) {
            let origin = latin1(storage_key_raw);
            if r.deleted {
                // A cleared metadata entry — no protobuf to parse, but the
                // tombstone itself is forensically meaningful.
                out.push(LocalStorageRecord::Meta {
                    origin,
                    timestamp_webkit_micros: 0,
                    size: None,
                    seq: r.seq,
                    deleted: true,
                });
            } else if let Some((timestamp_webkit_micros, size)) = parse_meta_protobuf(&r.value) {
                out.push(LocalStorageRecord::Meta {
                    origin,
                    timestamp_webkit_micros,
                    size,
                    seq: r.seq,
                    deleted: false,
                });
            } else {
                out.push(LocalStorageRecord::Other {
                    key: r.key.clone(),
                    seq: r.seq,
                    deleted: r.deleted,
                });
            }
        } else if r.key.first() == Some(&b'_') {
            let body = &r.key[1..];
            if let Some(nul) = body.iter().position(|&b| b == 0) {
                let origin = latin1(&body[..nul]);
                let script_key = decode_type_prefixed(&body[nul + 1..]);
                let value = if r.deleted {
                    StorageValue::empty()
                } else {
                    decode_type_prefixed(&r.value)
                };
                out.push(LocalStorageRecord::Data {
                    origin,
                    script_key,
                    value,
                    seq: r.seq,
                    deleted: r.deleted,
                });
            } else {
                out.push(LocalStorageRecord::Other {
                    key: r.key.clone(),
                    seq: r.seq,
                    deleted: r.deleted,
                });
            }
        } else {
            out.push(LocalStorageRecord::Other {
                key: r.key.clone(),
                seq: r.seq,
                deleted: r.deleted,
            });
        }
    }
    out
}
