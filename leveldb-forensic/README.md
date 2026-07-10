# leveldb-forensic

Chrome/Chromium **Local Storage** and **Session Storage** decoder built on
[`leveldb-core`](https://crates.io/crates/leveldb-core).

Decodes the type-prefixed value strings LevelDB-backed web storage uses
(UTF-16-LE / Latin-1), attributes each entry to its origin/host, and carries a
`lossy` flag on any value that failed to decode cleanly — surfaced with its raw
bytes, never dropped or panicked on. Iterates **every** record, including
tombstones and orphaned entries.

```rust
use leveldb_forensic::decode_local_storage;

for entry in decode_local_storage("Local Storage/leveldb".as_ref())? {
    // entry.origin, entry.key, entry.value, entry.lossy, entry.seq, entry.deleted
}
```

Part of [leveldb-forensic](https://github.com/SecurityRonin/leveldb-forensic).
Licensed under Apache-2.0.
