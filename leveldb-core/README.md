# leveldb-core

Pure-Rust, read-only, panic-free **LevelDB record reader** for forensics.

Enumerates every raw record from an existing LevelDB directory — all `.ldb`
SSTables and `.log` write-ahead logs — **without taking the `LOCK` and without
mutating the directory**, surfacing the records a normal merged `Get()` hides:

- **tombstones** (deletion markers),
- **superseded versions** (old values a newer write shadowed), and
- each record's **sequence number** and origin file.

```rust
use leveldb_core::read_dir;

for rec in read_dir("Local Storage/leveldb".as_ref())? {
    // Record { key, value, seq, deleted, origin_file }
}
```

`#![forbid(unsafe_code)]`, panic-free by lint (every length/offset/count read
through bounds-checked helpers), and validated against the independent
`rusty-leveldb` oracle. Part of
[leveldb-forensic](https://github.com/SecurityRonin/leveldb-forensic).

Licensed under Apache-2.0.
