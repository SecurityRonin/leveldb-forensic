# 5. MSRV split — low CI-verified floor for the libraries, pinned toolchain for the binary

Date: 2026-07-24
Status: Accepted

## Context

The constitution's **Rust MSRV & Toolchain Policy** separates the *dev toolchain*
(what we build with) from the *declared MSRV* (`rust-version`, a downstream-facing
promise), and sets the declared MSRV by repo *role*: published libraries keep a
low, CI-verified MSRV as a compatibility signal; apps/binaries declare the pinned
toolchain, since nothing pins a library dependency against them. This repo
publishes two libraries **and** ships one binary, so both rules apply within one
workspace.

## Decision

1. **`rust-toolchain.toml` pins the dev toolchain to `1.96.0`** (the current fleet
   stable, single source of truth) with `rustfmt` + `clippy` components declared
   in-file.
2. **The published libraries declare a low floor**: `leveldb-core` and
   `leveldb-forensic` set `rust-version = "1.80"` (member `Cargo.toml`), a
   deliberate compatibility signal distinct from the dev pin — raised only if a
   newer-Rust feature is genuinely needed.
3. **The binary declares the pinned toolchain**: `leveldb4n6` sets `rust-version =
   "1.96"` (member `Cargo.toml`), matching exactly what it is built and tested
   with.

## Consequences

- Third-party consumers can link `leveldb-core` / `leveldb-forensic` on Rust as
  old as 1.80; a CI MSRV job must hold that floor honest.
- The binary's release build must install `1.96.0` (matching
  `rust-toolchain.toml`) in cross-compiling jobs, or the target lands on the wrong
  toolchain (`E0463`) — the fleet release gotcha.
- Raising a library's declared MSRV later narrows its crates.io audience and is
  treated as a near-breaking change, not a routine bump.
