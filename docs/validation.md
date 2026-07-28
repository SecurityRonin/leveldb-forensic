# Validation

How `leveldb-forensic` earns its correctness claims, tier by tier (see the
Evidence-Based Rigor tiers: 1 = independent third party authors artifact *and*
answer key, or real-world data; 2 = real engine output whose ground truth is
derivable from the documented construction; 3 = self-authored fixture/property,
legitimate only where no external oracle exists).

## `leveldb-core` — the record reader (tier 2, independent oracle)

The reader is validated against an **independent implementation of the writer**:
the pure-Rust [`rusty-leveldb`](https://crates.io/crates/rusty-leveldb) crate (a
separate reimplementation of LevelDB, not our code) *writes* real on-disk files,
and our reader reads them back. The test (`leveldb-core/tests/oracle.rs`) does:

1. Open a disk-backed `rusty-leveldb` database with a tiny `write_buffer_size`
   (256 bytes) so the memtable spills to real L0 `.ldb` SSTables while the
   current memtable stays in the `.log`. **No compaction is triggered** —
   compaction to the bottom level would drop the tombstones and superseded
   versions that are the forensic payload.
2. Write 40 keys, overwrite one (`key007`: `ORIGINAL` → `UPDATED`), delete one
   (`key013`), and `flush()`.
3. Assert both a `.ldb` and a `.log` file were produced (both code paths run).
4. Read the directory with **our** reader and assert:
   - **(a) live view matches the oracle** — for every live key, our
     highest-`seq` non-deleted record equals what `rusty-leveldb`'s own `get()`
     returns;
   - **(b) the hidden records surface** — the `key013` **deletion tombstone**
     and the superseded `ORIGINAL` value of `key007` both appear (a merged
     `get()` view hides them), with `seq(UPDATED) > seq(ORIGINAL)`.

A second test writes a long, highly compressible value so the SSTable stores a
**Snappy-compressed** block (compression type 1), confirming the decompression
path recovers the exact bytes.

Ground truth is derivable from the construction (we chose the writes) and
cross-checked by an independent implementation of the writer — tier 2. The one
gap: `rusty-leveldb` is a Rust *reimplementation*, not Google's C++ reference, so
on-disk byte-for-byte compatibility with the C++ `leveldb`/Chromium writer is
**not** independently confirmed here. The format constants are taken from the
official LevelDB [table format](https://github.com/google/leveldb/blob/main/doc/table_format.md)
and [log format](https://github.com/google/leveldb/blob/main/doc/log_format.md)
specs. Reconciling against a Chromium-authored corpus is the natural tier-1
follow-up.

## Robustness (tier 3, property tests + fuzz)

`leveldb-core/tests/robustness.rs` feeds truncated footers, wrong magic, lying
varint lengths, oversized lengths, and arbitrary bytes to the public parsers and
asserts the property *"returns `Err` (or empty), never panics"*. These are
tier-3 property tests — the value-producing correctness is covered by the oracle
above; here the invariant is a property, not a value.

The runtime backstop is `cargo-fuzz` (`fuzz/`): four "must not panic" targets —
`parse_table`, `parse_log`, `decode_local`, `decode_session`. Local smoke runs
executed 7.1M / 2.9M / 0.7M / 1.9M cases respectively with no crashes and bounded
memory; `fuzz.yml` runs them on a weekly schedule.

## `leveldb-forensic` — Chrome storage decode (tier 2/3)

The decoders are validated two ways (`leveldb-forensic/tests/decode.rs`):

- **End-to-end through the oracle** — `rusty-leveldb` writes Chrome-shaped
  Local Storage entries (`_origin\x00script_key` data keys with type-prefixed
  values), our `read_dir` reads them, and the decoder recovers the value and
  surfaces a deleted key as a tombstone. The LevelDB layer is oracle-backed and
  the decoded string's ground truth is derivable from how the value was encoded.
- **Direct format tests** — constructed records whose key/value bytes follow the
  documented ccl_chromium_reader format: UTF-16-LE and Latin-1 values, a
  lone-surrogate value (asserts `lossy = true` with raw bytes retained, no
  panic), the `META:` protobuf (timestamp + size), `VERSION` → `Other`, and the
  Session Storage `namespace-`↔`map-` host join.

- **Real Chromium-authored fixture (tier 2)** — a genuine Google Chrome
  (150.0.7871.187, headless) was driven to a page running four known
  `localStorage.setItem` writes; its `Local Storage/leveldb` directory is
  committed at `tests/data/chromium-local-storage/leveldb`.
  `leveldb-forensic/tests/real_chromium_local_storage.rs` decodes the directory
  with `decode_local_storage` and asserts each write with its origin, value, and
  Chromium-chosen encoding (Latin-1 for the ASCII values, UTF-16-LE for the
  non-Latin-1 `unicode` value), plus the origin `META:` record. The bytes are
  real Chrome output; the ground truth is the four documented writes — tier 2
  (real engine output, construction-derived ground truth). Provenance and the
  reproducible mint command are in
  [`tests/data/README.md`](../tests/data/README.md) (`mint.sh`) and the fleet
  catalog (entry **D13**).

The value/key **format definitions** are taken from
[`cclgroupltd/ccl_chromium_reader`](https://github.com/cclgroupltd/ccl_chromium_reader)
(`ccl_chromium_localstorage.py`, `ccl_chromium_sessionstorage.py`). The decode
layer is now confirmed against a **real Chrome profile** (above), closing the
"live profile" gap for Local Storage; a full **differential** cross-check against
`ccl_chromium_reader` (the Python reader) on a large real-world profile remains
the tier-1 follow-up.

## Known edge cases not yet validated against an oracle

- **C++/Chromium-authored SSTables** — the record *reader* is validated against
  the `rusty-leveldb` reimplementation. The real-Chrome Local Storage fixture
  (D13) exercises the **`.log` (WAL) path** written by Chromium's own C++
  LevelDB, but the small dataset stayed in the memtable/log and produced **no
  `.ldb` SSTable**, so a *Chromium-authored SSTable* is still not exercised
  (that needs a larger real profile that has flushed/compacted an L0 table).
- **Non-Snappy compression** — LevelDB defines only none (0) and Snappy (1); Zstd
  and other types are reported as `UnknownCompression` (with the type byte and
  offset) and skipped loudly, but no such block was exercised.
- **Multi-block fragmented WAL records** spanning three or more 32 KiB blocks
  (FIRST/MIDDLE.../LAST) — reassembly is implemented and unit-reasoned but a
  real oracle-written record large enough to span ≥3 blocks was not produced.
- **Session Storage namespace GUIDs containing `-`** — the split mirrors ccl's
  `split("-", 2)`; if a GUID contains dashes the guid/host boundary follows ccl's
  (documented) behaviour rather than a semantic parse.
