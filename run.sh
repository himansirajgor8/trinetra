#!/usr/bin/env bash
# One-command start on Linux / Raspberry Pi / Termux. Creates a virtual environment on first run, then starts Trinetra.
#   ./run.sh --port 8080
set -e; cd "$(dirname "$0")"
[ -d .venv ] || { python3 -m venv .venv; .venv/bin/pip install -q -r requirements.txt; }
exec .venv/bin/python app/server.py "$@"
