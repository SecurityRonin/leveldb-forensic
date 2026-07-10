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

/// Read a LEB128 varint at `start`. Returns the value and bytes consumed, or
/// `None` if truncated or overlong. Bounds-checked; never panics.
fn read_varint(data: &[u8], start: usize) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    let mut i = start;
    while let Some(&byte) = data.get(i) {
        if shift >= 64 {
            return None; // overlong for u64
        }
        result |= u64::from(byte & 0x7f) << shift;
        i += 1;
        if byte & 0x80 == 0 {
            return Some((result, i - start));
        }
        shift += 7;
    }
    None
}

/// Parse the `StorageMetadata` protobuf: field 1 (tag `0x08`) is the WebKit-µs
/// timestamp varint; optional field 2 (tag `0x10`) is the size varint.
fn parse_meta_protobuf(data: &[u8]) -> Option<(u64, Option<u64>)> {
    let (tag1, n) = read_varint(data, 0)?;
    if tag1 != 0x08 {
        return None;
    }
    let (timestamp, n2) = read_varint(data, n)?;
    let pos = n + n2;

    // Optional field 2 (tag 0x10): the declared size in bytes.
    let mut size = None;
    if let Some((tag2, tn)) = read_varint(data, pos) {
        if tag2 == 0x10 {
            if let Some((sz, _)) = read_varint(data, pos + tn) {
                size = Some(sz);
            }
        }
    }
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
