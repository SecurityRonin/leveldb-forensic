//! Chrome/Chromium Local Storage record types.
//!
//! Reference: cclgroupltd/ccl_chromium_reader `ccl_chromium_localstorage.py`.
//! A `Local Storage/leveldb` directory holds three key shapes:
//! * `META:` + storage_key → a small protobuf (`0x08` timestamp varint,
//!   `0x10` size varint) — origin-level metadata.
//! * `_` + storage_key + `0x00` + script_key → a type-prefixed value string.
//! * `VERSION` and other bookkeeping keys.

use crate::value::StorageValue;

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
