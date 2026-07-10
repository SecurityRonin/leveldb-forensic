//! Pure-Rust, read-only, panic-free LevelDB record reader for forensics.
//!
//! Enumerates every raw record from an existing LevelDB directory — all `.ldb`
//! SSTables and `.log` write-ahead logs — **without taking the `LOCK` and
//! without mutating the directory**, surfacing the records a normal merged
//! `Get()` hides: deletion tombstones, superseded older versions, and each
//! record's global sequence number.
//!
//! ```no_run
//! for rec in leveldb_core::read_dir("Local Storage/leveldb".as_ref())? {
//!     println!("{:?} seq={} deleted={}", rec.key, rec.seq, rec.deleted);
//! }
//! # Ok::<(), leveldb_core::Error>(())
//! ```
//!
//! The on-disk formats are the LevelDB
//! [table format](https://github.com/google/leveldb/blob/main/doc/table_format.md)
//! and [log format](https://github.com/google/leveldb/blob/main/doc/log_format.md).
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod error;
mod record;

pub use error::Error;
pub use record::Record;

use std::path::Path;

/// Read every record from a LevelDB directory: all `*.ldb`/`*.sst` SSTables and
/// `*.log` write-ahead logs.
///
/// Opening the directory is the bootstrap step — if it cannot be read this
/// returns [`Error::Io`] loudly rather than an empty result. A single corrupt
/// *file* within an otherwise-valid directory is a per-artifact miss: it is
/// skipped and the remaining files are still read. Use [`parse_table_bytes`] /
/// [`parse_log_bytes`] directly when you need the per-file error.
pub fn read_dir(_dir: &Path) -> Result<Vec<Record>, Error> {
    // GREEN implementation lands next.
    Ok(Vec::new())
}

/// Parse a single SSTable (`.ldb`) file's bytes into records.
pub fn parse_table_bytes(_buf: &[u8], _origin: &Path) -> Result<Vec<Record>, Error> {
    // GREEN implementation lands next.
    Ok(Vec::new())
}

/// Parse a single write-ahead log (`.log`) file's bytes into records.
pub fn parse_log_bytes(_buf: &[u8], _origin: &Path) -> Result<Vec<Record>, Error> {
    // GREEN implementation lands next.
    Ok(Vec::new())
}
