#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 tools/update.py --target 1500 --check
