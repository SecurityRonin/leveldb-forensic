//! `leveldb4n6` — read-only LevelDB forensic CLI (library half).
//!
//! Humble object: every decision lives here as testable functions; `main.rs` is
//! a thin shell that parses arguments and calls [`run`]. Dumps raw records or
//! decoded Chrome Local/Session Storage as human `text`, or machine-faithful
//! `jsonl` / `csv`.
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod render;

use std::fmt;
use std::io::Write;
use std::path::Path;

use clap::ValueEnum;

/// Output format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Human-readable, one field-labelled line per record.
    Text,
    /// One JSON object per line — machine-faithful and round-trippable.
    Jsonl,
    /// Comma-separated values with a header row — machine-faithful.
    Csv,
}

/// What to decode the directory as.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    /// Raw LevelDB records (key/value as hex, with seq + tombstone flag).
    Raw,
    /// Chrome/Chromium Local Storage.
    Local,
    /// Chrome/Chromium Session Storage.
    Session,
}

/// A CLI failure: reading the evidence directory, or writing output.
#[derive(Debug)]
pub enum CliError {
    /// Failed to read the LevelDB directory.
    Read(leveldb_core::Error),
    /// Failed to write output.
    Write(std::io::Error),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Read(e) => write!(f, "reading LevelDB directory: {e}"),
            CliError::Write(e) => write!(f, "writing output: {e}"),
        }
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CliError::Read(e) => Some(e),
            CliError::Write(e) => Some(e),
        }
    }
}

/// Read `dir` and write every record to `out` in the chosen mode and format.
///
/// Reading the directory is the bootstrap: a missing or unreadable directory is
/// a loud [`CliError::Read`], never a silent empty dump.
pub fn run(dir: &Path, mode: Mode, format: Format, out: &mut dyn Write) -> Result<(), CliError> {
    let records = leveldb_core::read_dir(dir).map_err(CliError::Read)?;
    let result = match mode {
        Mode::Raw => render::render_raw(&records, format, out),
        Mode::Local => {
            let decoded = leveldb_forensic::decode_local_storage_records(&records);
            render::render_local(&decoded, format, out)
        }
        Mode::Session => {
            let decoded = leveldb_forensic::decode_session_storage_records(&records);
            render::render_session(&decoded, format, out)
        }
    };
    result.map_err(CliError::Write)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    #[test]
    fn clierror_display_and_source_for_both_variants() {
        let read = CliError::Read(leveldb_core::read_dir(Path::new("/no/such/dir")).unwrap_err());
        let write = CliError::Write(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe"));
        assert!(read.to_string().contains("reading LevelDB directory"));
        assert!(write.to_string().contains("writing output"));
        assert!(read.source().is_some());
        assert!(write.source().is_some());
    }
}
