//! `leveldb4n6` CLI entry point (thin humble-object shell).
//!
//! Parses arguments and delegates to [`leveldb4n6::run`]; all logic lives in the
//! library so it is unit-testable.
#![forbid(unsafe_code)]

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use leveldb4n6::{run, Format, Mode};

/// Read-only LevelDB forensic CLI.
#[derive(Parser)]
#[command(name = "leveldb4n6", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Dump every record from a LevelDB directory (tombstones included).
    Dump {
        /// The LevelDB directory (raw, or a Chrome Local/Session Storage folder).
        dir: PathBuf,
        /// How to decode the directory.
        #[arg(short, long, value_enum, default_value_t = Mode::Raw)]
        mode: Mode,
        /// Output format.
        #[arg(short, long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let Command::Dump { dir, mode, format } = cli.command;

    let stdout = io::stdout();
    let mut out = stdout.lock();
    match run(&dir, mode, format, &mut out) {
        Ok(()) => {
            let _ = out.flush();
            ExitCode::SUCCESS
        }
        Err(e) => {
            let _ = writeln!(io::stderr(), "leveldb4n6: {e}");
            ExitCode::FAILURE
        }
    }
}
