[![Docs](https://img.shields.io/badge/docs-securityronin.github.io-blue.svg)](https://securityronin.github.io/leveldb-forensic/)
[![CI](https://github.com/SecurityRonin/leveldb-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/leveldb-forensic/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](#trust-but-verify)
[![security: cargo-deny](https://img.shields.io/badge/security-cargo--deny-success.svg)](deny.toml)

# leveldb-forensic

**The deleted keys are the evidence — and a normal LevelDB `Get()` can't see them.** `leveldb4n6` enumerates *every* raw record in a LevelDB directory — Chrome history, extension state, Local/Session Storage — including the **tombstones and superseded versions** the merged database view hides, each carrying its **sequence number** and origin file. It opens the evidence read-only, never takes the `LOCK`, and never writes to the directory.

```bash
cargo install --path leveldb4n6
leveldb4n6 dump "Local Storage/leveldb"        # every record, tombstones included
```

**[Full documentation →](https://securityronin.github.io/leveldb-forensic/)**

---

## See it in 30 seconds

```console
$ leveldb4n6 dump "Local Storage/leveldb" -f text
origin=https://mail.example.com  key=theme     value=dark          seq=41  deleted=false
origin=https://mail.example.com  key=session   value=<UTF-16>...    seq=39  deleted=false
origin=https://mail.example.com  key=draft      value=              seq=44  deleted=TRUE
```

The `deleted=TRUE` row is a **tombstone**: a key the browser deleted, recovered from the WAL with the sequence number that orders it against the live writes. A normal LevelDB reader merges these away; a forensic reader surfaces them.

Point it at a raw LevelDB directory instead and you get the raw key/value records; point it at `Session Storage/` and it decodes the namespace/map structure. Choose `-f jsonl` or `-f csv` for a pipe-friendly, round-trippable stream.

---

## Why not just use a LevelDB library?

A normal LevelDB binding gives you the **merged view**: the current value of each live key, with deletions and old versions already discarded — exactly the forensic payload thrown away. `leveldb-core` instead walks the raw file structures directly:

| Layer | What it reads | What it surfaces |
|---|---|---|
| `.ldb` SSTable | Footer → index block → data blocks (prefix-compressed, optional Snappy, crc32c-checked) | every internal key with its `seq` and value-type (value / **deletion**) |
| `.log` WAL | 32 KiB blocks → physical-record fragments → reassembled `WriteBatch` | every `Put`/`Delete` op with its `seq` |

Both are read without opening the database, so an active browser's `LOCK` is never contended and the evidence directory is never mutated.

## Three crates

- **`leveldb-core`** — the pure-Rust, `#![forbid(unsafe_code)]`, panic-free-by-lint raw reader. `read_dir(path) -> Vec<Record>`.
- **`leveldb-forensic`** — Chrome/Chromium Local Storage and Session Storage decoding on top of `leveldb-core` records.
- **`leveldb4n6`** — the read-only CLI.

## Trust, but verify

`leveldb-core` is validated against an **independent oracle**: the pure-Rust [`rusty-leveldb`](https://crates.io/crates/rusty-leveldb) reimplementation writes real `.ldb`/`.log` files with known overwrites and deletes; our reader then reads them back and confirms (a) live records match what `rusty-leveldb` wrote and (b) the superseded and deleted records — which `rusty-leveldb`'s merged view hides — *also* surface. See [`docs/validation.md`](https://securityronin.github.io/leveldb-forensic/validation/).

Every parser is panic-free by lint (`clippy::unwrap_used`/`expect_used = deny`), all lengths/offsets are bounds-checked before use, and each on-disk structure (footer, data block, log record) has a `cargo-fuzz` target asserting "must not panic" on arbitrary input.

---

[Privacy Policy](https://securityronin.github.io/leveldb-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/leveldb-forensic/terms/) · © 2026 Security Ronin Ltd
