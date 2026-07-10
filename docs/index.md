# leveldb-forensic

**Enumerate every raw LevelDB record — including the tombstones and superseded versions the merged database view hides — without taking the `LOCK` or writing a byte.**

```rust
use leveldb_core::read_dir;

for rec in read_dir("Local Storage/leveldb".as_ref())? {
    // rec.key, rec.value, rec.seq, rec.deleted, rec.origin_file
}
```

**[GitHub Repository →](https://github.com/SecurityRonin/leveldb-forensic)**

---

## What it does

`leveldb-core` reads the raw LevelDB on-disk format — the `.ldb` SSTables and the `.log` write-ahead log — and surfaces the records a normal `Get()` never returns:

- **Tombstones** (deletion markers) — the record that proves *when* a key was deleted.
- **Superseded versions** — older values of a key that a newer write shadowed but never erased.
- **Sequence numbers** — LevelDB's global write order, letting you reconstruct a timeline.

`leveldb-forensic` decodes Chrome/Chromium **Local Storage** and **Session Storage** on top of those records: type-prefixed values (UTF-16-LE / Latin-1), origin/host attribution, and a `lossy` flag on any value that failed to decode cleanly — surfaced, never dropped.

`leveldb4n6` is the read-only CLI: point it at a LevelDB directory and dump records as text, JSONL, or CSV.

See the [validation report](validation.md) for how correctness is checked against an independent oracle.
