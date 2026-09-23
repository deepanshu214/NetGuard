#!/usr/bin/env bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

echo "=========================================================="
echo " Starting NetGuard (Computer Networks Capstone Project)"
echo " Dashboard will be available at: http://127.0.0.1:5050"
echo "=========================================================="

if [ -f "./.venv/bin/python" ]; then
    ./.venv/bin/python netguard/main.py --port 5050 "$@"
else
    python3 netguard/main.py --port 5050 "$@"
fi
