//! Chrome/Chromium Local Storage and Session Storage decoder built on
//! [`leveldb_core`].
//!
//! Decodes the type-prefixed value strings LevelDB-backed web storage uses
//! (UTF-16-LE / Latin-1), attributes each entry to its origin/host, and carries
//! a `lossy` flag on any value that failed to decode cleanly — surfaced with its
//! raw bytes, never dropped or panicked on. Iterates **every** record, including
//! tombstones and orphaned entries.
//!
//! Reference: cclgroupltd/ccl_chromium_reader (`ccl_chromium_localstorage.py`,
//! `ccl_chromium_sessionstorage.py`).
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod localstorage;
mod sessionstorage;
mod value;

pub use localstorage::LocalStorageRecord;
pub use sessionstorage::SessionStorageRecord;
pub use value::{Encoding, StorageValue};

use leveldb_core::Record;
use std::path::Path;

/// Decode Local Storage records from raw LevelDB [`Record`]s.
pub fn decode_local_storage_records(_records: &[Record]) -> Vec<LocalStorageRecord> {
    // GREEN implementation lands next.
    Vec::new()
}

/// Read a `Local Storage/leveldb` directory and decode its records.
pub fn decode_local_storage(dir: &Path) -> Result<Vec<LocalStorageRecord>, leveldb_core::Error> {
    let records = leveldb_core::read_dir(dir)?;
    Ok(decode_local_storage_records(&records))
}

/// Decode Session Storage records from raw LevelDB [`Record`]s.
pub fn decode_session_storage_records(_records: &[Record]) -> Vec<SessionStorageRecord> {
    // GREEN implementation lands next.
    Vec::new()
}

/// Read a `Session Storage` directory and decode its records.
pub fn decode_session_storage(
    dir: &Path,
) -> Result<Vec<SessionStorageRecord>, leveldb_core::Error> {
    let records = leveldb_core::read_dir(dir)?;
    Ok(decode_session_storage_records(&records))
}
