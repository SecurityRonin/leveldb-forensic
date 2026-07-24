# leveldb-forensic — Product Requirements

*Reverse-written from the shipped code (grounded in a same-session read of the
workspace on 2026-07-24). The load-bearing decisions live as ADRs
[0001](decisions/0001-three-crate-core-forensic-cli-split.md)–[0008](decisions/0008-independent-oracle-validation-and-output-formats.md)
under [`docs/decisions/`](decisions/). This document describes what the tool is
and does today; it is not a forward plan.*

## Executive Summary

**The deleted keys are the evidence, and a normal LevelDB `Get()` cannot see
them.** `leveldb4n6` is a read-only command-line tool that enumerates *every* raw
record in a LevelDB directory — Chrome/Chromium history, extension state,
Local Storage, Session Storage — including the **deletion tombstones** and
**superseded versions** the merged database view discards. Each record carries its
global **sequence number** and origin file, so an examiner can order a deleted
write against the live ones.

It opens the evidence **read-only**: it never acquires the LevelDB `LOCK`, never
runs recovery or compaction, and never writes to the directory — so it is safe to
run against a live browser's storage or a write-protected image
([ADR 0003](decisions/0003-read-only-lock-free-acquisition.md)).

The repo ships three crates: `leveldb-core` (the pure-Rust, `forbid(unsafe)`,
panic-free raw reader), `leveldb-forensic` (Chrome Local/Session Storage
decoding), and `leveldb4n6` (the CLI)
([ADR 0001](decisions/0001-three-crate-core-forensic-cli-split.md)).

## 1. Problem — what a normal LevelDB reader throws away

LevelDB is a log-structured key/value store: writes append to a write-ahead log
(`.log`) and flush into immutable, sorted SSTables (`.ldb`). A key is never
updated in place — an overwrite appends a new record with a higher sequence
number, and a delete appends a **tombstone**. The old value and the tombstone
persist on disk until compaction eventually drops them.

A normal LevelDB binding answers `Get(key)` from the **merged view**: it returns
the current value of each live key and hides everything else. For forensics, the
hidden records *are the case* — the value a suspect deleted, the earlier draft
they overwrote, the order in which they did it. A reader built on a LevelDB
library would merge that evidence away before the examiner saw it
([ADR 0002](decisions/0002-parse-raw-structures-surface-tombstones.md)).

## 2. Users and use case

- **DFIR analysts / examiners** triaging a browser profile: recovering deleted
  Local Storage entries, superseded Session Storage values, and the sequence
  ordering between them — from a live host, a mounted image, or an extracted
  directory.
- **Tool builders / the Issen fleet**: linking `leveldb-core` for raw LevelDB
  records, or `leveldb-forensic` for decoded Chrome storage, without the CLI.

The fastest path an examiner cares about:

```console
$ leveldb4n6 dump "Local Storage/leveldb" -f text
origin=https://mail.example.com  key=theme    value=dark        seq=41  deleted=false
origin=https://mail.example.com  key=draft     value=            seq=44  deleted=TRUE
```

The `deleted=TRUE` row is a tombstone recovered from the WAL, ordered by `seq`
against the live writes.

## 3. What it does

1. **Raw record enumeration** (`leveldb-core`): reads every `*.ldb`/`*.sst`
   SSTable and `*.log` WAL in a directory into `Vec<Record>`, each record carrying
   key, value, `seq`, and `deleted`. Honours prefix compression, optional Snappy
   blocks (compression type 1), and masked crc32c trailers. Format constants from
   Google's published table/log-format specs
   ([ADR 0002](decisions/0002-parse-raw-structures-surface-tombstones.md)).
2. **Chrome/Chromium storage decoding** (`leveldb-forensic`): decodes
   type-prefixed value strings (UTF-16-LE / Latin-1), Local Storage `META:`
   protobuf metadata (WebKit-µs timestamp + size), the `_`-prefixed storage-key /
   script-key structure, and Session Storage `namespace-`/`map-` records — every
   value retaining its raw bytes and a `lossy` flag so a lossy decode can never
   pass as clean ([ADR 0006](decisions/0006-chrome-storage-decoding-lossy-secure-by-design.md)).
   The `META:` protobuf is decoded through the fleet's `protobuf-forensic-core`
   ([ADR 0007](decisions/0007-prefer-our-own-protobuf-forensic-core.md)).
3. **Read-only CLI** (`leveldb4n6`): `dump <dir>` in `raw`, `local`, or `session`
   mode, output as `text` (human), `jsonl`, or `csv` (machine-faithful,
   round-trippable) ([ADR 0008](decisions/0008-independent-oracle-validation-and-output-formats.md)).
   A humble-object shell — every decision lives in the testable library half,
   `main.rs` only parses arguments.

## 4. Scope

- Read and enumerate LevelDB SSTable (`.ldb`/`.sst`) and WAL (`.log`) records,
  including tombstones and superseded versions, with sequence numbers.
- Decode Chrome/Chromium Local Storage and Session Storage.
- Render to `text` / `jsonl` / `csv`.
- Read-only, `LOCK`-free, non-mutating access.

## 5. Non-goals

- **No merged/queried view.** This is deliberately *not* a LevelDB `Get()`; it
  does not deduplicate or resolve keys to a current value.
- **No writing, recovery, or compaction** — never mutates the evidence
  ([ADR 0003](decisions/0003-read-only-lock-free-acquisition.md)).
- **Not a general LevelDB library.** It surfaces raw records for forensics, not a
  read/write embedded database.
- **No application decoders beyond Chrome Local/Session Storage** today (e.g. IndexedDB
  decoding is out of scope for this repo as it stands).
- **No MANIFEST/version-set replay** — records are read from the files present,
  not reconstructed from the version history.

## 6. Artifact family

LevelDB directories as used by Chromium-family browsers: `Local Storage/leveldb`,
`Session Storage`, and other LevelDB-backed stores (extension state, site data).
On-disk formats: LevelDB
[table_format](https://github.com/google/leveldb/blob/main/doc/table_format.md)
(`.ldb` SSTable) and
[log_format](https://github.com/google/leveldb/blob/main/doc/log_format.md)
(`.log` WAL).

## 7. Validation approach

- **`leveldb-core` vs an independent oracle** (`rusty-leveldb`, a separate pure-Rust
  LevelDB reimplementation): the oracle *writes* real `.ldb`/`.log` files with
  known overwrites and deletes; our reader reads them back and confirms the live
  view matches the oracle's `get()` **and** the superseded/deleted records the
  oracle's merged view hides also surface. Tier 2 evidence
  ([ADR 0008](decisions/0008-independent-oracle-validation-and-output-formats.md),
  [`docs/validation.md`](validation.md)).
- **Robustness**: `forbid(unsafe)`, panic-free by lint (`unwrap_used`/`expect_used
  = deny`), bounds-checked cursor, and a `cargo-fuzz` target per on-disk structure
  asserting "must not panic" on arbitrary input
  ([ADR 0004](decisions/0004-forbid-unsafe-panic-free-bounds-checked-fuzzed.md)).
- **Known gap (stated, not hidden)**: `rusty-leveldb` is a Rust reimplementation,
  not Google's C++ reference, so byte-for-byte compatibility with the C++
  `leveldb`/Chromium writer is not independently confirmed here
  ([`docs/validation.md`](validation.md)).
