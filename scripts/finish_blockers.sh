#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ ! -x .venv/bin/python ]]; then
  echo 'INCONCLUSIVE: existing virtualenv is unavailable.' >&2
  exit 2
fi
source .venv/bin/activate
export PATH="$HOME/.local/bin:$PATH"
exec python -m engine.finish_blockers
