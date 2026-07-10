//! Error type for the LevelDB reader.
//!
//! Every variant carries the offending value and its offset so an "unknown /
//! invalid X" is never a dead end — the raw bytes and location travel with the
//! error (fail-loud, show-the-value discipline).

use std::fmt;
use std::path::PathBuf;

/// Errors returned while reading a LevelDB directory or parsing an on-disk
/// structure. Parsing is panic-free: every malformed input becomes one of these
/// rather than a panic or over-allocation.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Ran off the end of the buffer while reading `what` at byte `offset`.
    UnexpectedEof {
        /// Name of the field being read.
        what: &'static str,
        /// Byte offset within the structure where the read began.
        offset: usize,
    },
    /// A LEB128 varint was truncated or overflowed its target width.
    BadVarint {
        /// Byte offset where the varint began.
        offset: usize,
    },
    /// A length/offset/count read from the file exceeds the bytes available.
    LengthOutOfRange {
        /// Name of the field carrying the length.
        what: &'static str,
        /// The offending value.
        value: u64,
        /// The bytes actually available.
        available: u64,
        /// Byte offset where the length was read.
        offset: usize,
    },
    /// SSTable footer magic did not match `0xdb4775248b80fb57`. Carries the
    /// eight bytes actually found so the caller can identify the file.
    BadTableMagic {
        /// The eight magic bytes found (verbatim).
        found: [u8; 8],
        /// Byte offset of the magic field.
        offset: usize,
    },
    /// A block trailer's masked crc32c did not match the computed value.
    BadBlockCrc {
        /// The masked crc stored in the trailer.
        stored: u32,
        /// The masked crc computed over the block.
        computed: u32,
        /// Byte offset of the block.
        offset: usize,
    },
    /// A block trailer named a compression type the reader does not implement
    /// (only `0` = none and `1` = Snappy are defined by the format).
    UnknownCompression {
        /// The unrecognised compression type byte.
        kind: u8,
        /// Byte offset of the trailer.
        offset: usize,
    },
    /// Failed to read a file or directory entry.
    Io {
        /// The path that failed.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnexpectedEof { what, offset } => {
                write!(
                    f,
                    "unexpected end of input reading {what} at offset {offset}"
                )
            }
            Error::BadVarint { offset } => {
                write!(f, "malformed varint at offset {offset}")
            }
            Error::LengthOutOfRange {
                what,
                value,
                available,
                offset,
            } => write!(
                f,
                "{what} length {value} exceeds {available} available bytes at offset {offset}"
            ),
            Error::BadTableMagic { found, offset } => write!(
                f,
                "bad SSTable footer magic at offset {offset}: found {found:02x?} \
                 (expected db4775248b80fb57 little-endian)"
            ),
            Error::BadBlockCrc {
                stored,
                computed,
                offset,
            } => write!(
                f,
                "block crc32c mismatch at offset {offset}: stored {stored:#010x}, \
                 computed {computed:#010x}"
            ),
            Error::UnknownCompression { kind, offset } => {
                write!(
                    f,
                    "unknown block compression type {kind} at offset {offset}"
                )
            }
            Error::Io { path, source } => {
                write!(f, "I/O error reading {}: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}
