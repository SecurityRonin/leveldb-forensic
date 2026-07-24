# 4. `forbid(unsafe)`, panic-free-by-lint, bounds-checked cursor, per-structure fuzzing

Date: 2026-07-24
Status: Accepted

## Context

Every byte these crates read is attacker-controllable: a LevelDB directory pulled
from a suspect device can be arbitrarily malformed — truncated footers, lying
varint lengths, oversized block handles, corrupt fragment chains. The
constitution's **Paranoid Gatekeeper** standard (MANDATORY for every `*-core` /
`*-forensic` crate) requires: never panic, never read out of bounds, never trust a
length field; `forbid(unsafe)` where no mmap is needed; panic-free lints; and one
fuzz target per parsed structure.

## Decision

1. **`#![forbid(unsafe_code)]`** in every crate root (`leveldb-core`,
   `leveldb-forensic`, `leveldb4n6` `lib.rs`) and `unsafe_code = "forbid"` in
   `[workspace.lints.rust]`. This reader needs **no** `unsafe`: it uses
   `std::fs::read` into owned `Vec<u8>` rather than `mmap`, so — unlike the fleet's
   mmap readers (`ewf`, `memory-forensic`) that must downgrade to `deny` + a
   bounded `#[allow]` — it keeps the stronger, badge-able `forbid`.
2. **Panic-free by lint**: `[workspace.lints.clippy]` sets `unwrap_used = deny`
   and `expect_used = deny`, plus `correctness`/`suspicious = deny`; tests opt out
   via `#![cfg_attr(test, allow(...))]` and `clippy.toml`
   (`allow-unwrap-in-tests`).
3. **All reads go through a bounds-checked cursor** (`leveldb-core/src/bytes.rs`
   `Cursor`): every `take`/length-prefixed read is length-checked and
   `checked_add`-guarded before indexing, returning `Error::UnexpectedEof` rather
   than panicking; length-prefixed reads cap the claimed length at the bytes
   actually remaining so a hostile varint cannot drive an over-allocation.
4. **One `cargo-fuzz` target per on-disk structure** (`fuzz/fuzz_targets/`):
   `parse_table`, `parse_log`, `decode_local`, `decode_session` — each asserting
   "must not panic" on arbitrary input. The fuzz crate is a standalone workspace
   excluded from `cargo deny` (`deny.toml [graph] exclude`).

## Consequences

- The README's paired robustness claim holds the fleet form: "input-fuzzed"
  (measured evidence) beside "panic-free by lint" (the static posture) — never a
  bare panic-free absolute.
- The `unsafe forbidden` badge is earned, not asserted.
- **Deviation from the `safe-read` rule, documented honestly.** The constitution
  says route fixed-width integer reads through the shared `safe-read` crate and
  never hand-roll a per-crate `bytes.rs`. `safe-read` covers fixed-width integer
  *fields* only; LevelDB's on-disk encoding is dominated by LEB128 varints (read
  via the `integer-encoding` crate) behind a *stateful, length-prefix-capping*
  cursor, which `safe-read` does not provide. The `bytes.rs` `Cursor` is that
  stateful layer. **Rationale reconstructed from structure; the original intent to
  hand-roll rather than adopt/extend `safe-read` is not recorded in the commit
  history** — a future pass should evaluate re-expressing the fixed-width reads
  inside `Cursor` on top of `safe-read` to bring it back under the shared audited
  implementation.
