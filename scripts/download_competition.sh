#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA="$ROOT/data"
COMPETITION="ai-agent-security-multi-step-tool-attacks"

mkdir -p "$DATA"
kaggle competitions download -c "$COMPETITION" -p "$DATA"
unzip -qo "$DATA/${COMPETITION}.zip" -d "$DATA/sdk"
echo "Competition SDK extracted to $DATA/sdk"
