#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/submission"
ARCHIVE="$OUT/submission.zip"

rm -rf "$OUT"
mkdir -p "$OUT/agent_security"

cp "$ROOT/attack.py" "$OUT/"
rsync -a --exclude '__pycache__' --exclude '*.pyc' "$ROOT/src/agent_security/" "$OUT/agent_security/"

(
  cd "$OUT"
  zip -rq "$ARCHIVE" attack.py agent_security
)

echo "Created $ARCHIVE"
