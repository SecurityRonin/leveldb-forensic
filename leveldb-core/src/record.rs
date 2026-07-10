//! The forensic record type surfaced by the reader.

use std::path::PathBuf;

/// One raw LevelDB record recovered from an SSTable (`.ldb`) or the write-ahead
/// log (`.log`).
///
/// Unlike a normal merged `Get()`, the reader surfaces **every** record: live
/// values, superseded older versions, and deletion tombstones. The [`seq`]
/// (global sequence number) orders every write in the database, and [`deleted`]
/// marks a tombstone.
///
/// [`seq`]: Record::seq
/// [`deleted`]: Record::deleted
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// The user key (the 8-byte internal-key trailer already stripped).
    pub key: Vec<u8>,
    /// The value bytes. Empty for a deletion tombstone.
    pub value: Vec<u8>,
    /// The global sequence number ordering this write against all others.
    pub seq: u64,
    /// `true` if this record is a deletion tombstone (value-type 0).
    pub deleted: bool,
    /// The `.ldb`/`.log` file this record was recovered from.
    pub origin_file: PathBuf,
}
