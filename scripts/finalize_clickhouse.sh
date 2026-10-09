#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
source .venv/bin/activate
python - <<'PY'
import json
import os
import subprocess
from pathlib import Path

from engine.events import ROOT
from engine.integrations import process_artifact
from engine.replay import export_replay, public_run

def main():
    manifest = json.loads((ROOT / 'web/evidence.json').read_text())
    wanted = {run['run_id']: run['source_sha256'] for run in manifest['runs']}
    if len(wanted) != 2:
        raise RuntimeError('Expected exactly two recorded runs')
    paths = {}
    for path in (ROOT / 'evidence').rglob('*.json'):
        if path.stem not in wanted:
            continue
        try:
            run = public_run(path)
        except (RuntimeError, ValueError, KeyError, TypeError):
            continue
        if run['source_sha256'] == wanted[run['run_id']]:
            paths[run['run_id']] = path
    if set(paths) != set(wanted):
        raise RuntimeError('Original verified artifacts unavailable')
    for run_id in wanted:
        result = process_artifact(paths[run_id], cloud=True, github=False)
        receipt = result.get('clickhouse', {})
        if receipt.get('status') != 'PASS' or receipt.get('readback_verified') is not True:
            print('ClickHouse INCONCLUSIVE:', receipt.get('reason', 'Readback unverified'))
            print('Stopped after this failure. Public receipts and production unchanged.')
            return 2
        print('ClickHouse PASS:', run_id, receipt['events_verified'], 'events uploaded and read back')
    link = json.loads((ROOT / '.vercel/project.json').read_text())
    if (link.get('projectId') != 'prj_O4zlIRaRWbNHW8WwoxAvUMnYJXn0'
            or link.get('orgId') != 'team_J49jXmAXIjsAiupWY0z18yHN'):
        raise RuntimeError('Unexpected linked Vercel project')
    export_replay([paths[run_id] for run_id in wanted])
    env = {k: v for k, v in os.environ.items()
           if k not in ('OPENAI_API_KEY', 'CLICKHOUSE_PASSWORD', 'GH_TOKEN', 'GITHUB_TOKEN')}
    subprocess.run(['node', 'scripts/build_site.mjs'], cwd=ROOT, env=env, check=True)
    subprocess.run(['npx', '--yes', 'vercel@63.1.0', 'deploy', '--prod', '--scope', 'vincentleg'],
                   cwd=ROOT, env=env, check=True)
    print('PASS: both ClickHouse receipts verified and production deployment completed.')
    return 0

try:
    raise SystemExit(main())
except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError):
    print('INCONCLUSIVE: finalization could not complete; any verified local receipts are preserved.')
    raise SystemExit(2)
PY
