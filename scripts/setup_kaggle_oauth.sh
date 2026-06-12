#!/usr/bin/env bash
# Switch Kaggle CLI from settings-page token to OAuth (full API permissions).
set -euo pipefail

KAGGLE_DIR="${HOME}/.kaggle"
mkdir -p "$KAGGLE_DIR"
chmod 700 "$KAGGLE_DIR"

if [[ -f "${KAGGLE_DIR}/access_token" ]]; then
  backup="${KAGGLE_DIR}/access_token.bak.$(date +%Y%m%d%H%M%S)"
  mv "${KAGGLE_DIR}/access_token" "$backup"
  echo "Backed up access_token → $backup"
fi

echo ""
echo "Starting Kaggle OAuth login (opens browser, scope: resources.admin:*)..."
echo ""

kaggle auth login --force

echo ""
echo "OAuth login complete."
kaggle config view
echo ""
kaggle competitions list 2>&1 | head -3
