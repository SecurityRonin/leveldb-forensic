# 3. Read-only, LOCK-free acquisition — never contend the `LOCK`, never mutate the directory

Date: 2026-07-24
Status: Accepted

## Context

LevelDB evidence is frequently examined while the owning application is still
running (an open browser holds `Local Storage/leveldb` and `Session Storage`).
Opening the database the normal way acquires the exclusive `LOCK` file and can
trigger recovery/compaction — both of which either fail against a live process or
mutate the evidence directory, destroying the very tombstones and superseded
versions this tool exists to recover. Forensic soundness requires the evidence be
read without modification (the constitution's Secure-by-Design axiom and the
"evidence editor" caution in the naming grammar).

## Decision

1. **Read files with plain `std::fs::read`** and never open a LevelDB database
   handle. `leveldb-core::read_dir` (`leveldb-core/src/lib.rs`) lists the
   directory, reads each `*.ldb`/`*.sst`/`*.log` file's bytes, and parses them in
   memory. The `LOCK` file is never acquired, so a live application's lock is
   never contended.
2. **Never write to the evidence directory** — no recovery, no compaction, no
   manifest rewrite; the code has no write path at all.
3. **Bootstrap fails loud; a per-file miss degrades to skip** (constitution
   Robustness rule): if the *directory* cannot be read, `read_dir` returns
   `Error::Io` loudly rather than an empty result; a single corrupt *file* within
   an otherwise-valid directory is a per-artifact miss and is skipped so the
   remaining files still read. `parse_table_bytes` / `parse_log_bytes` are exposed
   for callers that need the per-file error.

## Consequences

- The tool is safe to run against a mounted, running, or write-protected evidence
  source; the README's read-only promise ("opens the evidence read-only, never
  takes the `LOCK`, and never writes to the directory") is structural, not
  advisory.
- Whole files are read into memory rather than streamed; acceptable because
  individual `.ldb`/`.log` files are bounded (LevelDB targets a few MiB per
  SSTable, 32 KiB-blocked logs), and it keeps the reader `forbid(unsafe)` with no
  mmap (see ADR 0004).
- Reading a directory that a live process is *actively* writing can observe a
  torn file; this is treated as a per-file parse miss (skip) rather than a hard
  failure, consistent with the degrade-after-bootstrap rule above.
