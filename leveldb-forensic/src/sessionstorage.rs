//! Chrome/Chromium Session Storage record types.
//!
//! Reference: `cclgroupltd/ccl_chromium_reader` `ccl_chromium_sessionstorage.py`.
//! A `Session Storage` directory holds two key shapes (each decoded as UTF-8,
//! then split on `-` into three parts):
//! * `namespace-` + guid + `-` + host → value is the map-id (joins a host to a
//!   map).
//! * `map-` + map_id + `-` + script_key → value is the stored string.

use std::collections::HashMap;

use crate::value::{decode_session_value, StorageValue};
use leveldb_core::Record;

const NAMESPACE_PREFIX: &[u8] = b"namespace-";
const MAP_PREFIX: &[u8] = b"map-";

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

/// A namespace/map key decoded as UTF-8 and split into three `-`-separated parts
/// (`prefix`, middle, tail), matching ccl's `key.split("-", 2)`.
fn split3(key: &str) -> Option<(&str, &str)> {
    let mut parts = key.splitn(3, '-');
    let _prefix = parts.next()?;
    let middle = parts.next()?;
    let tail = parts.next()?;
    Some((middle, tail))
}

/// Decode Session Storage records. A first pass links each map-id to its host via
/// the `namespace-` records; the second pass emits every record (namespace, map,
/// or other) with the host attached to map entries where known.
pub(crate) fn decode(records: &[Record]) -> Vec<SessionStorageRecord> {
    let mut host_by_map: HashMap<String, String> = HashMap::new();
    for r in records {
        if r.deleted
            || !r.key.starts_with(NAMESPACE_PREFIX)
            || r.key.len() == NAMESPACE_PREFIX.len()
        {
            continue;
        }
        if let Ok(key) = std::str::from_utf8(&r.key) {
            if let Some((_guid, host)) = split3(key) {
                if let Ok(map_id) = std::str::from_utf8(&r.value) {
                    host_by_map
                        .entry(map_id.to_string())
                        .or_insert_with(|| host.to_string());
                }
            }
        }
    }

    let mut out = Vec::with_capacity(records.len());
    for r in records {
        if r.key.starts_with(NAMESPACE_PREFIX) && r.key.len() != NAMESPACE_PREFIX.len() {
            match std::str::from_utf8(&r.key).ok().and_then(split3) {
                Some((guid, host)) => out.push(SessionStorageRecord::Namespace {
                    guid: guid.to_string(),
                    host: host.to_string(),
                    map_id: String::from_utf8_lossy(&r.value).into_owned(),
                    seq: r.seq,
                    deleted: r.deleted,
                }),
                None => out.push(other(r)),
            }
        } else if r.key.starts_with(MAP_PREFIX) {
            match std::str::from_utf8(&r.key).ok().and_then(split3) {
                Some((map_id, script_key)) => {
                    let host = host_by_map.get(map_id).cloned();
                    let value = if r.deleted {
                        StorageValue::empty()
                    } else {
                        decode_session_value(&r.value)
                    };
                    out.push(SessionStorageRecord::Map {
                        map_id: map_id.to_string(),
                        host,
                        script_key: script_key.to_string(),
                        value,
                        seq: r.seq,
                        deleted: r.deleted,
                    });
                }
                None => out.push(other(r)),
            }
        } else {
            out.push(other(r));
        }
    }
    out
}

fn other(r: &Record) -> SessionStorageRecord {
    SessionStorageRecord::Other {
        key: r.key.clone(),
        seq: r.seq,
        deleted: r.deleted,
    }
}
