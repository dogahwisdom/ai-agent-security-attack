#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
"$ROOT/scripts/verify_kaggle_oauth.sh"

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  VERSION="$(kaggle kernels status wisdomdogah/jed-attack-submission 2>&1 | grep -oE 'version [0-9]+' | awk '{print $2}' || true)"
fi
if [[ -z "$VERSION" ]]; then
  echo "Usage: submit_competition.sh <kernel-version>" >&2
  echo "Push first: ./scripts/push_kernel.sh" >&2
  exit 1
fi

MSG="${2:-v0.1 MultiStepExplorer — modular Go-Explore attack pipeline}"

echo ""
echo "Submitting kernel version ${VERSION}..."
if kaggle competitions submit ai-agent-security-multi-step-tool-attacks \
  -f submission.csv \
  -k wisdomdogah/jed-attack-submission \
  -v "$VERSION" \
  -m "$MSG"; then
  echo "CLI submit succeeded."
  kaggle competitions submissions -c ai-agent-security-multi-step-tool-attacks | head -8
  exit 0
fi

echo ""
echo "CLI submit failed. Use the Kaggle UI:"
echo "  1. https://www.kaggle.com/competitions/ai-agent-security-multi-step-tool-attacks/submit"
echo "  2. Notebook: JED Attack Submission"
echo "  3. Version: ${VERSION}"
echo "  4. Submit"
exit 1
