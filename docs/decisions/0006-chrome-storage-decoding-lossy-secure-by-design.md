# 6. Chrome storage decoding — reference `ccl_chromium_reader`, type-prefixed values, lossy-flag secure-by-design

Date: 2026-07-24
Status: Accepted

## Context

Chrome/Chromium store Local Storage and Session Storage inside a LevelDB
directory, but the raw records are not directly readable: values are
**type-prefixed strings** (a one-byte encoding prefix + body), keys are
structured (`META:` / `_`-prefixed storage keys, `namespace-` / `map-` shapes),
and the raw bytes come from a suspect device — so a decoder must tolerate
malformed input without losing evidence or panicking. The community reference for
this format is `cclgroupltd/ccl_chromium_reader`
(`ccl_chromium_localstorage.py`, `ccl_chromium_sessionstorage.py`).

## Decision

1. **Decode against the `ccl_chromium_reader` reference** (cited in the module
   docs of `leveldb-forensic/src/{localstorage,sessionstorage,value}.rs`):
   - **Values** (`value.rs`): type prefix `0x00` = UTF-16-LE, `0x01` = Latin-1
     (`iso-8859-1`); any other prefix is malformed.
   - **Local Storage** (`localstorage.rs`): `META:` + storage_key → protobuf
     origin metadata; `_` + storage_key + `0x00` + script_key → a value string;
     `VERSION`/bookkeeping keys. `META:` timestamps are WebKit microseconds (µs
     since 1601-01-01 UTC).
   - **Session Storage** (`sessionstorage.rs`): `namespace-`guid`-`host → map-id;
     `map-`id`-`script_key → value; joined host↔map by map-id.
2. **Decoding never fails, never panics, never drops bytes** (constitution
   Robustness "show the unrecognized value"): the return type
   `StorageValue { text, raw, encoding, lossy }` (`value.rs`) always retains the
   **raw** bytes verbatim, substitutes U+FFFD for undecodable units, and carries
   an `Encoding::Unknown(u8)` variant that keeps the unrecognised prefix byte.
3. **The `lossy` flag is structural, not a side-channel** (constitution
   Secure-by-Design — "return types carry security-relevant state"): any lossy
   decode or unknown prefix sets `lossy = true`, so a caller cannot mistake a
   lossy decode for a clean one.
4. **Every record surfaces, including tombstones and orphans** — decoding iterates
   all `Record`s from `leveldb-core`, carrying each record's `seq` and `deleted`
   flag through (a `map-` entry with no matching `namespace-` record surfaces with
   `host: None` rather than being dropped).

## Consequences

- The decoder is medium-agnostic: it accepts `leveldb-core::Record`s and never
  reaches below `leveldb-core`, consistent with the PARSER dependency rule.
- An examiner sees the raw bytes for any value the decoder could not cleanly
  interpret, never a silent substitution presented as truth.
- Fidelity to Google's C++ Chromium writer rests on the `ccl_chromium_reader`
  reference plus the oracle in ADR 0007, not on a Chromium-authored answer key
  (stated gap in `docs/validation.md`).
