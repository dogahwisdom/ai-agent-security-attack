#!/usr/bin/env bash
set -euo pipefail

echo "=== Kaggle OAuth check ==="
kaggle config view

auth_method="$(kaggle config view 2>&1 | awk -F': ' '/auth_method/ {print $2}')"
if [[ "$auth_method" != "OAUTH" ]]; then
  echo "ERROR: Expected auth_method OAUTH, got: ${auth_method:-unknown}" >&2
  echo "Run: kaggle auth login --force" >&2
  exit 1
fi

if [[ ! -f "${HOME}/.kaggle/credentials.json" ]]; then
  echo "ERROR: Missing ~/.kaggle/credentials.json" >&2
  exit 1
fi

echo ""
echo "=== API smoke test ==="
kaggle competitions list -s "ai-agent-security" | head -3

echo ""
echo "=== Kernel status ==="
kaggle kernels status wisdomdogah/jed-attack-submission

echo ""
echo "=== Latest kernel outputs ==="
kaggle kernels files wisdomdogah/jed-attack-submission | grep -E 'submission.csv|attack.py' || true

echo ""
echo "Submit UI: https://www.kaggle.com/competitions/ai-agent-security-multi-step-tool-attacks/submit"
echo "  Notebook: JED Attack Submission → T4 GPU version → submission.csv (not attack.py)"
echo "Kernel (check Version History on the right): https://www.kaggle.com/code/wisdomdogah/jed-attack-submission"
echo "If the submit dropdown stops at v3: open the kernel → Save & Run All (GPU) → retry submit."

echo ""
echo "OAuth OK. Ready to submit."
