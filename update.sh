#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"
TARGET="${TARGET:-1500}"
WORKERS="${WORKERS:-128}"

command -v "$PYTHON" >/dev/null 2>&1 || {
  echo "[ERROR] Python 3 not found. Set PYTHON=/path/to/python3."
  exit 1
}

"$PYTHON" tools/update.py --target "$TARGET" --check --geoip --workers "$WORKERS"

echo "[OK] Neo VPN subscription updated."
echo "[INFO] Output: output/neo_vpn.txt"
