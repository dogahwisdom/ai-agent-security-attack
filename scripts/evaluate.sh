#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# shellcheck disable=SC1091
source "${ROOT}/.venv/bin/activate"
export PYTHONPATH="${ROOT}/data/sdk:${PYTHONPATH:-}"

BUDGET_S="${BUDGET_S:-60}"
AGENT="${AGENT:-deterministic}"
ARTIFACTS="${ARTIFACTS:-$ROOT/artifacts}"

mkdir -p "$ARTIFACTS"

python -m aicomp_sdk.cli.main evaluate redteam attack.py \
  --budget-s "$BUDGET_S" \
  --agent "$AGENT" \
  --env gym \
  --artifacts-dir "$ARTIFACTS" \
  --verbosity progress
