#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
rm -f "$ROOT/kaggle_kernel/jed_attack_submission.ipynb"
"$ROOT/scripts/build_kaggle_notebook.py"
cd "$ROOT/kaggle_kernel"
PUSH_LOG="$(mktemp)"
if ! kaggle kernels push -p . 2>&1 | tee "$PUSH_LOG"; then
  rm -f "$PUSH_LOG"
  exit 1
fi
PUSHED_VERSION="$(grep -oE 'Kernel version [0-9]+' "$PUSH_LOG" | awk '{print $3}' || true)"
rm -f "$PUSH_LOG"

echo ""
echo "Kernel: https://www.kaggle.com/code/wisdomdogah/jed-attack-submission"
[[ -n "$PUSHED_VERSION" ]] && echo "Pushed version: ${PUSHED_VERSION}"
echo "Waiting for notebook run..."

for _ in $(seq 1 40); do
  status="$(kaggle kernels status wisdomdogah/jed-attack-submission 2>&1 | tail -1)"
  echo "$status"
  if echo "$status" | grep -q COMPLETE; then
    echo ""
    echo "Notebook run complete."
    if kaggle kernels files wisdomdogah/jed-attack-submission | grep -q submission.csv; then
      echo "Output includes submission.csv."
    else
      echo "Warning: submission.csv not in output yet."
    fi
    if [[ -n "$PUSHED_VERSION" ]]; then
      echo ""
      echo "Submit via UI → Version ${PUSHED_VERSION} (or highest in Version History)"
      echo "  ./scripts/submit_competition.sh ${PUSHED_VERSION}"
    fi
    exit 0
  fi
  if echo "$status" | grep -qE 'ERROR|FAILED|CANCELLED'; then
    kaggle kernels logs wisdomdogah/jed-attack-submission | tail -20
    exit 1
  fi
  sleep 20
done
