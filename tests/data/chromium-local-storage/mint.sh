#!/usr/bin/env bash
# Mint a REAL Chromium-authored Local Storage leveldb store for tier-2 validation.
#
# Drives a genuine Google Chrome (headless) to the committed `mint.html`, which
# runs four known `localStorage.setItem` writes. Chrome persists them to its
# profile's `Local Storage/leveldb` directory; we copy the store files out. The
# bytes are real Chromium output; the ground truth is those four documented
# writes (see this dir's parent `tests/data/README.md`).
#
# Deterministic origin: the page is served over a fixed local port, so every
# leveldb key is `_http://127.0.0.1:8117\x00<script_key>`.
#
# Usage:  ./mint.sh                 # writes ./leveldb/ next to this script
#         CHROME="/path/to/chrome" ./mint.sh
#
# Requires: Google Chrome / Chromium and python3 (for the static server).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT=8117
DEST="$HERE/leveldb"
CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"; [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null || true' EXIT

# 1) Serve the mint page on a fixed origin.
( cd "$HERE" && python3 -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1 ) &
SRV_PID=$!
sleep 1

# 2) Drive headless Chrome with a throwaway profile; graceful shutdown flushes
#    the LocalStorageImpl commit timer to disk.
"$CHROME" --headless=new --disable-gpu --no-first-run --no-default-browser-check \
  --user-data-dir="$WORK/profile" \
  "http://127.0.0.1:$PORT/mint.html" >"$WORK/chrome.log" 2>&1 &
CHROME_PID=$!
sleep 10
kill -TERM "$CHROME_PID" 2>/dev/null || true
sleep 3
kill -KILL "$CHROME_PID" 2>/dev/null || true
wait "$CHROME_PID" 2>/dev/null || true

# 3) Copy the store files (CURRENT, MANIFEST-*, *.ldb, *.log). LOCK/LOG are
#    Chrome-runtime-only and not part of the forensic fixture.
SRC="$WORK/profile/Default/Local Storage/leveldb"
rm -rf "$DEST"; mkdir -p "$DEST"
for f in CURRENT MANIFEST-* *.ldb *.log; do
  [ -e "$SRC/$f" ] && cp "$SRC/$f" "$DEST/"
done
chmod 644 "$DEST"/*

echo "Minted $DEST:"; ls -l "$DEST"
command -v md5 >/dev/null && md5 "$DEST"/* || md5sum "$DEST"/*
