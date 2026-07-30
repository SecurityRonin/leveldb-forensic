//! Tier-1 **differential** validation against the independent Python oracle
//! [`cclgroupltd/ccl_chromium_reader`](https://github.com/cclgroupltd/ccl_chromium_reader).
//!
//! Where `real_chromium_local_storage.rs` asserts our decode against the four
//! *documented* writes (construction-derived ground truth, tier 2), this test
//! reconciles our `decode_local_storage` output against a **separate,
//! third-party re-implementation** reading the *same* on-disk bytes. Agreement
//! of two independent decoders on real Chromium output is tier-1 evidence: the
//! answer key is authored by someone else, not by us.
//!
//! ## Gating (skips cleanly unless both halves are present)
//! * `CCL_LEVELDB_ORACLE` — path to a Python interpreter that can
//!   `import ccl_chromium_reader` (e.g. a venv's `bin/python`). Unset ⇒ skip.
//! * `CCL_LEVELDB_DIR` — optional override pointing at a *larger* real Chromium
//!   `Local Storage/leveldb` directory. Defaults to the committed real-Chromium
//!   fixture (`tests/data/chromium-local-storage/leveldb`), so the differential
//!   runs against real bytes with zero setup once the oracle is available.
//!
//! When `CCL_LEVELDB_ORACLE` is set we *trust that assertion* and fail loud on
//! any oracle error (a broken interpreter is a bootstrap failure, never a silent
//! skip). Absence of the env var is the only clean-skip path.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::process::Command;

use leveldb_forensic::{decode_local_storage, LocalStorageRecord};

/// The committed real-Chromium fixture directory (workspace-root relative).
fn default_fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tests/data/chromium-local-storage/leveldb")
}

/// The bundled Python oracle driver (this test's private companion).
fn oracle_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/ccl_oracle.py")
}

/// Decode two hex nibbles.
fn unhex(s: &str) -> Vec<u8> {
    assert!(
        s.len().is_multiple_of(2),
        "odd-length hex from oracle: {s:?}"
    );
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex from oracle"))
        .collect()
}

fn unhex_str(s: &str) -> String {
    String::from_utf8(unhex(s)).expect("oracle emits UTF-8 hex")
}

/// What both decoders are reconciled on.
#[derive(Default)]
struct Sets {
    /// Origins carrying storage metadata.
    origins: BTreeSet<String>,
    /// Live `(origin, script_key, value)` triples.
    data: BTreeSet<(String, String, String)>,
}

/// Run the ccl oracle over `dir` and parse its hex-line output into [`Sets`].
fn oracle_sets(python: &str, dir: &std::path::Path) -> Sets {
    let out = Command::new(python)
        .arg(oracle_script())
        .arg(dir)
        .output()
        .unwrap_or_else(|e| panic!("failed to launch ccl oracle {python:?}: {e}"));
    assert!(
        out.status.success(),
        "ccl oracle exited {:?}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).expect("oracle stdout is UTF-8");
    let mut sets = Sets::default();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let mut f = line.split('\t');
        match f.next() {
            Some("ORIGIN") => {
                let origin = unhex_str(f.next().expect("ORIGIN storage_key"));
                sets.origins.insert(origin);
            }
            Some("DATA") => {
                let origin = unhex_str(f.next().expect("DATA origin"));
                let key = unhex_str(f.next().expect("DATA script_key"));
                let value = unhex_str(f.next().expect("DATA value"));
                sets.data.insert((origin, key, value));
            }
            other => panic!("unrecognised oracle line tag {other:?} in {line:?}"),
        }
    }
    sets
}

/// Collapse our full record stream (which keeps tombstones + superseded
/// versions) into the same *live view* ccl exposes: per `(origin, script_key)`,
/// the highest-`seq` record, kept only when it is not a deletion.
fn our_sets(recs: &[LocalStorageRecord]) -> Sets {
    let mut origins = BTreeSet::new();
    let mut best: HashMap<(String, String), (u64, bool, String)> = HashMap::new();
    for r in recs {
        match r {
            LocalStorageRecord::Meta {
                origin,
                deleted: false,
                ..
            } => {
                origins.insert(origin.clone());
            }
            LocalStorageRecord::Data {
                origin,
                script_key,
                value,
                seq,
                deleted,
            } => {
                let k = (origin.clone(), script_key.text.clone());
                let replace = best.get(&k).is_none_or(|(s, _, _)| *seq > *s);
                if replace {
                    best.insert(k, (*seq, *deleted, value.text.clone()));
                }
            }
            _ => {}
        }
    }
    let data = best
        .into_iter()
        .filter(|(_, (_, deleted, _))| !*deleted)
        .map(|((origin, key), (_, _, value))| (origin, key, value))
        .collect();
    Sets { origins, data }
}

#[test]
fn differential_matches_ccl_chromium_reader() {
    let Ok(python) = std::env::var("CCL_LEVELDB_ORACLE") else {
        eprintln!(
            "skipping ccl differential: set CCL_LEVELDB_ORACLE to a Python \
             interpreter that can `import ccl_chromium_reader`"
        );
        return;
    };
    if python.trim().is_empty() {
        eprintln!("skipping ccl differential: CCL_LEVELDB_ORACLE is empty");
        return;
    }

    let dir = std::env::var_os("CCL_LEVELDB_DIR").map_or_else(default_fixture_dir, PathBuf::from);
    assert!(
        dir.is_dir(),
        "CCL_LEVELDB_DIR / fixture is not a directory: {}",
        dir.display()
    );

    let ours = our_sets(&decode_local_storage(&dir).expect("our decoder reads the leveldb dir"));
    let theirs = oracle_sets(&python, &dir);

    // Real bytes must carry at least one live entry, or the differential proves
    // nothing (guards against pointing at an empty/wrong directory).
    assert!(
        !theirs.data.is_empty(),
        "ccl oracle found no live Local Storage records in {} — wrong directory?",
        dir.display()
    );

    assert_eq!(
        ours.data,
        theirs.data,
        "live (origin, script_key, value) sets diverge from ccl_chromium_reader\n\
         ours-only:   {:?}\n\
         theirs-only: {:?}",
        ours.data.difference(&theirs.data).collect::<Vec<_>>(),
        theirs.data.difference(&ours.data).collect::<Vec<_>>(),
    );

    // ccl only lists origins that carry a metadata record; ours must cover all
    // of them (we may additionally surface metadata-less origins, so ⊇, not ==).
    assert!(
        theirs.origins.is_subset(&ours.origins),
        "origins with metadata diverge\nours:   {:?}\ntheirs: {:?}",
        ours.origins,
        theirs.origins,
    );
}
