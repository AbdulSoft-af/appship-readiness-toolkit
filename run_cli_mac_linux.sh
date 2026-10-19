#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
PYTHON_CMD="python3"
if ! "$PYTHON_CMD" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)' >/dev/null 2>&1; then
  echo "ERROR: Python 3.10 or newer is required."
  exit 1
fi
exec "$PYTHON_CMD" -m appship.cli "$@"
