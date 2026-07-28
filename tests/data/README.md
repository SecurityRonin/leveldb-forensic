# Test data — `leveldb-forensic`

Provenance for every committed fixture. The single fleet-wide machine index is
[`ronin-issen/docs/test-data-catalog.md`](../../../../docs/test-data-catalog.md)
(entry **D13**) — this file is the co-located human detail; cross-reference, do
not duplicate.

Classification legend matches the fleet catalog: **REAL-self** = genuine
engine/tool output collected on a controlled host; **T2** = real engine output
whose ground truth is derivable from documented construction.

---

## `chromium-local-storage/leveldb/` · REAL-self · **T2**

A **real Chromium-authored** Local Storage `leveldb` store, minted on this host
by driving a genuine Google Chrome to a page that runs four known
`localStorage.setItem` writes. The bytes are real Chrome output; the ground
truth is the four documented writes. Consumed by
`leveldb-forensic/tests/real_chromium_local_storage.rs`, which decodes the
directory with `decode_local_storage` and asserts each write plus the origin
`META:` record — the tier-1/2 real-profile follow-up called out in
[`docs/validation.md`](../../docs/validation.md).

- **Source:** self-minted with Google Chrome 150.0.7871.187 (macOS, aarch64),
  headless. No third party; real browser engine output.
- **Origin (ground truth):** `http://127.0.0.1:8117` (the fixed local mint
  server, so every data key is `_http://127.0.0.1:8117\x00<script_key>`).
- **Known writes (ground truth):**

  | script key | value | Chromium on-disk encoding |
  |---|---|---|
  | `case_id` | `CASE-001` | Latin-1 (type prefix `0x01`) |
  | `greeting` | `Hello, forensics!` | Latin-1 (type prefix `0x01`) |
  | `count` | `42` | Latin-1 (type prefix `0x01`) |
  | `unicode` | `日本語 café ☕` | UTF-16-LE (type prefix `0x00`) |

  Chrome also writes an origin-level `META:` record (WebKit-µs last-modified
  timestamp + declared size) and a `VERSION` bookkeeping key; both surface via
  the decoder and are exercised by the test.

- **Verbatim generator (reproducible):** run the committed script (needs Google
  Chrome/Chromium + `python3`):
  ```
  tests/data/chromium-local-storage/mint.sh
  ```
  It serves the committed `mint.html` on `127.0.0.1:8117`, drives headless
  Chrome to it with a throwaway profile, gracefully shuts Chrome down (flushing
  the LocalStorage commit timer), then copies `CURRENT`, `MANIFEST-*`, `*.ldb`,
  and `*.log` out of `Default/Local Storage/leveldb`. `mint.html` holds the four
  `setItem` writes (single source of truth). The exact bytes vary per run only
  in the `META:` timestamp (real wall-clock) — the test asserts a plausible
  range for it, and exact equality for the four writes.
- **Files (committed, small):**

  | file | bytes | MD5 | SHA-256 |
  |---|---|---|---|
  | `leveldb/000003.log` | 319 | `7259318b8db2a78a96f2b32e257d9e97` | `711efb1d2b6e78687355d07bc527de4e5460d48ca615b9c9588511cd3a725f6d` |
  | `leveldb/CURRENT` | 16 | `46295cac801e5d4857d09837238a6394` | `0f1bad70c7bd1e0a69562853ec529355462fcd0423263a3d39d6d0d70b780443` |
  | `leveldb/MANIFEST-000001` | 41 | `5af87dfd673ba2115e2fcf5cfdb727ab` | `f9d31b278e215eb0d0e9cd709edfa037e828f36214ab7906f612160fead4b2b4` |

- **Redistribution:** no third-party or personal data — synthetic writes to a
  loopback origin, minted by us. Freely redistributable.
- **`LOCK` / `LOG`:** deliberately excluded — Chrome-runtime-only files, not part
  of the forensic store.
