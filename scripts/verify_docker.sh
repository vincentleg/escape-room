#!/bin/bash
# One local-only command: real Docker twice, Semgrep, and sanitized site export.
set +x
set -euo pipefail
ESCAPE_SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec "$ESCAPE_SCRIPT_DIR/local_verify.sh" --local-only
