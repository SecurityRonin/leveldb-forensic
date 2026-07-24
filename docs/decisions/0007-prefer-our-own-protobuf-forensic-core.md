# 7. Prefer our own crates — decode the `META:` protobuf via `protobuf-forensic-core`

Date: 2026-07-24
Status: Accepted

## Context

Local Storage `META:` records hold a small protobuf (field `0x08` = timestamp
varint, field `0x10` = size varint) carrying origin-level metadata. The initial
implementation hand-decoded this protobuf inline in `localstorage.rs`. The fleet
publishes `protobuf-forensic-core`, a schemaless protobuf wire-format decoder
built for exactly this job. The constitution's **Dependency Preference** rule is a
hard rule, not a tiebreaker: "Always prefer our own (SecurityRonin / `h4x0r`)
crates over third-party ones … If a third-party crate is wired in but we have (or
are building) our own equivalent, migrate to ours — proactively."

## Decision

**Migrate the `META:` decode to `protobuf-forensic-core`** rather than keep a
bespoke hand-rolled parser. Commit `8f53be6`
("refactor(localstorage): decode `META:` protobuf via protobuf-forensic-core")
replaced the inline decode with `protobuf_forensic_core::FieldValue` extraction
(`leveldb-forensic/src/localstorage.rs`); the dependency is declared in
`[workspace.dependencies]` as `protobuf-forensic-core = "0.1"` (the published
registry version, not a path dep).

## Consequences

- One audited, fuzzed protobuf decoder is reused instead of a second hand-rolled
  wire-format parser drifting inside this repo (DRY + robustness).
- `leveldb-forensic` gains a fleet dependency; when `protobuf-forensic-core`
  publishes new versions, this consumer bumps with the fleet rather than
  maintaining its own varint/tag reader.
- The migration is a genuine pivot recorded in history (`8f53be6`), so the
  rationale is grounded in the commit, not reconstructed.
