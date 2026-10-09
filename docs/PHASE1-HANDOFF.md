# Phase 1 handoff

Implemented the Docker runner, real probe scripts, normalized evidence, immutable policy baseline, deterministic event-driven response, CLI demo, CI gate, local Semgrep adapter, custom YAML rules, and focused tests. No frontend work was performed.

## Actual validation

- Two `engine.demo` attempts: exit **2**, **INCONCLUSIVE** at Docker daemon access. Zero successful three-act Docker runs; no runtime access/denial results were fabricated.
- Drifted configuration gate: exit **1**, blocked by the approved policy.
- Secure configuration-only gate: exit **0**, **configuration compliance only**.
- Secure runtime gate: exit **2**, **INCONCLUSIVE** at Docker daemon access.
- Semgrep installation: failed because package index network/DNS access is blocked. The rules and adapter remain **unverified against a real Semgrep installation**. There are no real Semgrep findings in this delivery.
- **38 focused tests pass.** They exercise explicit doubles and the shipped probe scripts against controlled I/O doubles, plus actual subprocess timeout/exit and SIGTERM handling. Their success is not Docker containment evidence.

See `evidence/recorded/43c4cac622574cdb87ef27b3daa99767.json` for the captured validation command report and the neighboring run artifacts for full normalized events. The earlier test report predates the final signal/static-output tests; the final test result is recorded separately.

## Commit delivery

The session's filesystem policy makes `/Users/vincentgppm/escape-room/.git` read-only, including creation: `git init` returns `Operation not permitted`. A source snapshot is therefore committed in a separate allowed temporary directory, then delivered as `phase1-source.bundle`. This does not turn the current workspace into a Git checkout. The commit hash is recorded in `COMMIT.txt`; the bundle contains source, tests, documentation, and authentic recorded evidence, excluding virtualenv and bundle artifacts.

To obtain a normal checkout outside this restricted session:

```sh
git clone /path/to/escape-room/phase1-source.bundle escape-room-phase1
cd escape-room-phase1
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-semgrep.txt
docker info
python -m unittest discover -s tests -v
python scripts/verify_twice.py --require-semgrep
```

## Remaining acceptance work

1. Run from an environment allowed to access the **local** Docker socket. Do not publish it or switch to an unauthenticated TCP daemon.
2. Install the free Semgrep CLI; validate both rules against both samples and preserve actual JSON findings.
3. Execute `python scripts/verify_twice.py --require-semgrep`; inspect both PASS summaries and the collector/canary/control events. Confirm cleanup before presenting the demonstration.
4. Only then begin Phase 2: consume successful evidence for a read-only three-act replay UI, label pending/inconclusive outcomes honestly, and keep Docker control out of public hosting.

Phase 2 has not been started.
