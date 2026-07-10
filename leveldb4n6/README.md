# leveldb4n6

Read-only **LevelDB forensic CLI**. Point it at a LevelDB directory (raw, or a
Chrome Local/Session Storage `leveldb` folder) and dump every record —
tombstones and superseded versions included — as text, JSONL, or CSV.

```console
$ leveldb4n6 dump "Local Storage/leveldb" -f text
$ leveldb4n6 dump "Session Storage" -f jsonl
$ leveldb4n6 dump ./some/leveldb -f csv --raw
```

It never takes the database `LOCK` and never writes to the directory. Part of
[leveldb-forensic](https://github.com/SecurityRonin/leveldb-forensic).

Licensed under Apache-2.0.
