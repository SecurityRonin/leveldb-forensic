#!/usr/bin/env python3
"""Independent-oracle driver for the leveldb-forensic ccl differential test.

Reads a Chromium ``Local Storage/leveldb`` directory with the third-party
``cclgroupltd/ccl_chromium_reader`` and emits its *live* view on stdout for the
Rust harness (``tests/differential_ccl.rs``) to reconcile against our own
``decode_local_storage``.

Install the oracle into a venv and point ``CCL_LEVELDB_ORACLE`` at that
interpreter:

    python3 -m venv /tmp/ccl-venv
    /tmp/ccl-venv/bin/pip install \\
        "git+https://github.com/cclgroupltd/ccl_chromium_reader.git"
    CCL_LEVELDB_ORACLE=/tmp/ccl-venv/bin/python \\
        cargo test -p leveldb-forensic --test differential_ccl

Output is a hex-encoded, tab-separated line stream (hex sidesteps every
delimiter/encoding hazard in real storage values):

    ORIGIN\t<hex utf-8 storage_key>              # one per metadata origin
    DATA\t<hex origin>\t<hex script_key>\t<hex value>   # one per live record

Only *live* (highest-seq, non-deleted) records are emitted, matching ccl's
``iter_all_records(include_deletions=False)`` — the Rust side collapses its
full tombstone-keeping stream to the same live view before comparing.
"""

import pathlib
import sys

from ccl_chromium_reader import ccl_chromium_localstorage as ls


def _hex(s: str) -> str:
    return s.encode("utf-8").hex()


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write("usage: ccl_oracle.py <leveldb-dir>\n")
        return 2
    leveldb_dir = pathlib.Path(argv[1])
    if not leveldb_dir.is_dir():
        sys.stderr.write(f"not a directory: {leveldb_dir}\n")
        return 2

    db = ls.LocalStoreDb(leveldb_dir)
    try:
        out = []
        for meta in db.iter_metadata():
            out.append(f"ORIGIN\t{_hex(meta.storage_key)}")
        for rec in db.iter_all_records(include_deletions=False):
            # A live record's value is never None; guard anyway rather than
            # emit a bogus row.
            if rec.value is None:
                continue
            out.append(
                "DATA\t"
                f"{_hex(rec.storage_key)}\t{_hex(rec.script_key)}\t{_hex(rec.value)}"
            )
    finally:
        db.close()

    sys.stdout.write("\n".join(out))
    if out:
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
