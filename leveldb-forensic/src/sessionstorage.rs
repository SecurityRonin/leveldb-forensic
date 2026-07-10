//! Chrome/Chromium Session Storage record types.
//!
//! Reference: cclgroupltd/ccl_chromium_reader `ccl_chromium_sessionstorage.py`.
//! A `Session Storage` directory holds two key shapes (each decoded as UTF-8,
//! then split on `-` into three parts):
//! * `namespace-` + guid + `-` + host → value is the map-id (joins a host to a
//!   map).
//! * `map-` + map_id + `-` + script_key → value is the stored string.

use crate::value::StorageValue;

/// One decoded Session Storage record. Deletion tombstones and superseded
/// versions surface too.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionStorageRecord {
    /// A `namespace-` record linking a host to a map-id.
    Namespace {
        /// The session namespace GUID.
        guid: String,
        /// The host this namespace belongs to.
        host: String,
        /// The map-id (from the value) that a host's entries live under.
        map_id: String,
        /// LevelDB sequence number.
        seq: u64,
        /// `true` if this is a deletion tombstone.
        deleted: bool,
    },
    /// A `map-` record: one stored key/value pair.
    Map {
        /// The map-id (from the key).
        map_id: String,
        /// The host owning this map, if a matching namespace record was found.
        host: Option<String>,
        /// The script-visible key.
        script_key: String,
        /// The stored value (decoded UTF-16-LE, prefix handled defensively).
        value: StorageValue,
        /// LevelDB sequence number.
        seq: u64,
        /// `true` if this is a deletion tombstone.
        deleted: bool,
    },
    /// A key that matched neither shape. Raw key bytes surfaced verbatim.
    Other {
        /// The raw user key.
        key: Vec<u8>,
        /// LevelDB sequence number.
        seq: u64,
        /// `true` if this is a deletion tombstone.
        deleted: bool,
    },
}
