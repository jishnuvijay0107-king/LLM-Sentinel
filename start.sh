#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
sentinel_python=".venv/bin/python"
if [ ! -x "$sentinel_python" ]; then
    echo "Create the environment with python3 -m venv .venv and install requirements.txt first."
    exit 1
fi
echo "Sentinel is starting at http://127.0.0.1:8501"
exec "$sentinel_python" -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8501
