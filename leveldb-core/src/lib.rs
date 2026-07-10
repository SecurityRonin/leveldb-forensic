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

mod bytes;
mod error;
mod log;
mod record;
mod sstable;

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
///
/// Files are read with plain `std::fs::read`; the LevelDB `LOCK` is never
/// acquired and the directory is never mutated.
pub fn read_dir(dir: &Path) -> Result<Vec<Record>, Error> {
    let entries = std::fs::read_dir(dir).map_err(|e| Error::Io {
        path: dir.to_path_buf(),
        source: e,
    })?;

    // Deterministic order so records read back in a stable sequence.
    let mut paths: Vec<std::path::PathBuf> = Vec::new();
    for entry in entries {
        // A per-entry iteration error means the directory bootstrap is
        // compromised, so surface it loudly rather than silently truncating the
        // listing. (A match, not a closure, keeps this a defensive line rather
        // than a separately-counted function.)
        match entry {
            Ok(e) => paths.push(e.path()),
            Err(e) => {
                return Err(Error::Io {
                    path: dir.to_path_buf(),
                    source: e,
                })
            }
        }
    }
    paths.sort();

    let mut records = Vec::new();
    for path in paths {
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .map(str::to_ascii_lowercase);
        match ext.as_deref() {
            Some("ldb" | "sst") => {
                if let Ok(buf) = std::fs::read(&path) {
                    // Per-file miss after a validated directory bootstrap: skip a
                    // corrupt SSTable, keep reading the rest.
                    if let Ok(mut recs) = parse_table_bytes(&buf, &path) {
                        records.append(&mut recs);
                    }
                }
            }
            Some("log") => {
                if let Ok(buf) = std::fs::read(&path) {
                    if let Ok(mut recs) = parse_log_bytes(&buf, &path) {
                        records.append(&mut recs);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(records)
}

/// Parse a single SSTable (`.ldb`) file's bytes into records. Returns `Err`
/// loudly (with the offending value + offset) on malformed input.
pub fn parse_table_bytes(buf: &[u8], origin: &Path) -> Result<Vec<Record>, Error> {
    sstable::parse_table(buf, origin)
}

/// Parse a single write-ahead log (`.log`) file's bytes into records. CRC-failed
/// or truncated physical records are skipped (forensic leniency); well-formed
/// batches are always emitted.
///
/// Log parsing is infallible today (it degrades over damage rather than
/// erroring), but the signature mirrors [`parse_table_bytes`] and reserves an
/// error channel for future strict modes.
#[allow(clippy::unnecessary_wraps)]
pub fn parse_log_bytes(buf: &[u8], origin: &Path) -> Result<Vec<Record>, Error> {
    Ok(log::parse_log(buf, origin))
}
