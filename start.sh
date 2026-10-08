#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
if ! command -v python3 >/dev/null 2>&1; then
  echo 'Python bulunamadı. Ubuntu: sudo apt install python3 python3-venv'
  exit 1
fi
if [ ! -x .venv/bin/python3 ]; then
  python3 -m venv .venv
fi
if ! .venv/bin/python3 -c 'import requests, dotenv' >/dev/null 2>&1; then
  .venv/bin/python3 -m pip install -r requirements.txt
fi
exec .venv/bin/python3 app.py "$@"
