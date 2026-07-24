# 8. Validate against an independent oracle (`rusty-leveldb`); render human vs machine-faithful output

Date: 2026-07-24
Status: Accepted

## Context

Two related correctness concerns, both governed by fleet standards:

1. **Validation.** A reader validated only by fixtures we hand-encoded to our own
   assumptions is the LZNT1 trap — green while wrong. The constitution's
   Doer-Checker / Evidence-Based Rigor tiers and the Test-Data Provenance standard
   require validation against an *independent* implementation or real-world data,
   not self-authored round-trips.
2. **Output.** The constitution's **Human vs Machine Output** discipline: human
   views render for eyes; machine views (`JSONL`, `CSV`) stay faithful and
   round-trippable, never truncated, `JSONL` preferred for a stream.

## Decision

1. **Validate `leveldb-core` against `rusty-leveldb` as an independent oracle**
   (`leveldb-core`/`leveldb-forensic` `[dev-dependencies]` `rusty-leveldb = "4"`;
   `leveldb-core/tests/oracle.rs`; commit `96828cd`; `docs/validation.md`).
   `rusty-leveldb` — a separate pure-Rust reimplementation of LevelDB, not our
   code — *writes* real `.ldb`/`.log` files with known overwrites and deletes; our
   reader reads them back and asserts (a) the live view matches `rusty-leveldb`'s
   own `get()`, and (b) the superseded and deleted records `get()` hides *also*
   surface. A second test forces a Snappy-compressed block. Tier 2 (ground truth
   derivable from the construction, cross-checked by an independent writer); the
   stated gap is that `rusty-leveldb` is a Rust reimplementation, not Google's C++
   reference.
2. **Three output formats, split by audience** (`leveldb4n6/src/render.rs`,
   `Format` enum in `leveldb4n6/src/lib.rs`):
   - `text` — human view: field-labelled, control characters flattened so a
     record stays on one line.
   - `jsonl` — machine view: one JSON object per line, control chars escaped as
     `\u00xx`, arbitrary bytes as hex, nothing truncated.
   - `csv` — machine view: RFC-4180-style quoting, header row, round-trippable.

## Consequences

- The differentiator ("hidden records surface") is proven by an oracle that
  *discards* those same records in its merged view — the strongest available check
  short of Google's C++ writer.
- Machine output is losslessly re-importable; the human `text` view is explicitly
  lossy-for-readability (one line per record) and is not the pipe format.
- Byte-for-byte compatibility with the C++ Chromium writer remains unproven here
  and is documented as a known gap in `docs/validation.md`, not papered over.
