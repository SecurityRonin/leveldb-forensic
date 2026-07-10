//! `leveldb4n6` — read-only LevelDB forensic CLI (library half).
//!
//! Humble object: every decision lives here as testable functions; `main.rs` is
//! a thin shell that parses arguments and calls [`run`]. Dumps raw records or
//! decoded Chrome Local/Session Storage as human `text`, or machine-faithful
//! `jsonl` / `csv`.
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

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
pub fn run(
    _dir: &Path,
    _mode: Mode,
    _format: Format,
    _out: &mut dyn Write,
) -> Result<(), CliError> {
    // GREEN implementation lands next.
    Ok(())
}
