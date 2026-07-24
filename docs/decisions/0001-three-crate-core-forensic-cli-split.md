# 1. Three-crate split: `leveldb-core` reader, `leveldb-forensic` decoder, `leveldb4n6` CLI

Date: 2026-07-24
Status: Accepted

## Context

LevelDB is a single on-disk format family (SSTable `.ldb` + write-ahead log
`.log`), but the work over it spans three concerns that age and are consumed
independently:

1. reading the *raw* records out of the on-disk structures;
2. interpreting those records as a specific application's data (here Chrome /
   Chromium Local Storage and Session Storage);
3. presenting the result to an examiner at a command line.

The fleet constitution (`ronin-issen/CLAUDE.md`) fixes the shape for exactly this
case: the **Crate-structure standard** ("reader/analyzer split — `core/` +
`forensic/`") and the **Crate naming grammar** Pattern A ("single-format repo …
exactly two crates: `<x>-core` reader + `<x>-forensic` analyzer", with an optional
`cli/` member whose binary follows the `<x>4n6` convention). The **Dependency
Preference** rule requires depending down onto our own crates.

## Decision

1. **Three workspace members** (`Cargo.toml` `members = ["leveldb-core",
   "leveldb-forensic", "leveldb4n6"]`):
   - `leveldb-core` — pure reader, `read_dir(path) -> Vec<Record>`; no application
     knowledge, no findings. Import path `leveldb_core` (`[lib] name =
     "leveldb_core"`).
   - `leveldb-forensic` — Chrome/Chromium storage decoder built on
     `leveldb-core`'s `Record` (`leveldb-forensic/src/lib.rs`).
   - `leveldb4n6` — the read-only CLI binary (the `<x>4n6` convention), depending
     on both libraries and `clap`.
2. **Dependency direction is one-way and downward**: `leveldb4n6` →
   `leveldb-forensic` → `leveldb-core`; the reader never depends on the decoder or
   the CLI. Wired via `[workspace.dependencies]` with `version` + `path` so each
   bump is one edit (`Cargo.toml`).
3. **Shared package fields inherited** from `[workspace.package]`
   (version/edition/license) so a release bumps one place.

## Consequences

- The reader is reusable by any consumer that wants raw LevelDB records without
  the Chrome-specific decoding — the split keeps `leveldb-core` a clean library
  leaf.
- Matches the fleet reference model (`ntfs-forensic`, `vmdk-forensic`): a reviewer
  moving between repos finds the same two-crate-plus-CLI shape.
- The bare crate name `leveldb` is a popular third-party crate on crates.io, so
  the import path is kept as `leveldb_core` (via `[lib] name`) rather than
  hijacking `leveldb::` — consistent with the naming-grammar rule for popular
  bare names (cf. `ntfs`).
