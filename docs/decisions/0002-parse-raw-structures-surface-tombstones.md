# 2. Parse the raw SSTable/WAL structures directly to surface tombstones and superseded versions

Date: 2026-07-24
Status: Accepted

## Context

A normal LevelDB binding answers `Get(key)` from the **merged view**: the current
value of each live key, with deletions and superseded older versions already
discarded during the read-path merge (and permanently dropped on compaction to
the bottom level). Those discarded records — deletion **tombstones** and
**superseded versions**, each ordered by a global **sequence number** — are
exactly the forensic payload. A reader built on a LevelDB library would throw
them away before the examiner ever saw them.

The constitution's Crate-structure standard anticipates this: "a `-core` reader is
built to read *valid* data robustly, so it abstracts away exactly the detail a
forensic auditor must SEE … forensic examination often needs to go much lower
level than the `-core` API." Here the requirement is even sharper — there is no
upstream reader whose happy path we could reuse without losing the evidence.

## Decision

**Walk the on-disk LevelDB structures directly**, never a merged database view:

1. **SSTable `.ldb`** (`leveldb-core/src/sstable.rs`): read the fixed 48-byte
   Footer (metaindex + index `BlockHandle` ‖ zero-pad to 40 ‖ 8-byte magic
   `0xdb4775248b80fb57` little-endian), follow the index block to each data
   block, and decode the prefix-compressed entries. Each internal key's trailing
   8 bytes are `(seq << 8) | value_type` (`value_type` 0 = deletion, 1 = value),
   so every record surfaces with its sequence number and whether it is a
   tombstone. Block trailers carry a 1-byte compression type (0 none / 1 Snappy)
   and a masked crc32c (u32 LE), both honoured.
2. **WAL `.log`** (`leveldb-core/src/log.rs`): read the 32 KiB blocks →
   7-byte-headered physical records (masked crc32c ‖ u16 LE length ‖ type) →
   reassemble FULL/FIRST/MIDDLE/LAST fragments into a `WriteBatch` (seq u64 LE ‖
   count u32 LE, then `count` ops); op `i` gets sequence `seq + i`. Every `Put`
   and `Delete` surfaces with its sequence.
3. **Enumerate every record** — the public entry point is `read_dir(path) ->
   Vec<Record>` returning *all* records from *all* files, not a keyed lookup;
   deduplication/merging is deliberately not performed.

Format constants are taken from Google's published
[table_format](https://github.com/google/leveldb/blob/main/doc/table_format.md)
and [log_format](https://github.com/google/leveldb/blob/main/doc/log_format.md)
specs (cited in the module docs).

## Consequences

- The differentiator holds: `deleted=TRUE` tombstones and superseded values that
  a merged `Get()` hides appear in output, each with the `seq` that orders it
  against the live writes.
- Snappy decompression and crc32c verification are on the critical path, pulling
  the `snap` and `crc32c` dependencies into `leveldb-core`.
- On-disk byte-for-byte compatibility with Google's C++ writer is asserted from
  the spec and cross-checked only against a Rust reimplementation, not the C++
  reference — see ADR 0007 and the stated gap in `docs/validation.md`.
