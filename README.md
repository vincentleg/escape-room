# ESCAPE ROOM — Autonomous Containment & Recovery

A minimal Python security engine demonstrating **two specific containment controls** in disposable local Docker containers, with a static public evidence-replay interface. No model API, paid runtime dependency, or external probe target.

## Phase 2 public demo

The CRISIS DRILL interface is built in `web/` and prepared for static Vercel deployment. It replays genuine local evidence and never controls Docker from the browser. Until a successful recording is exported, it explicitly shows evidence pending.

```sh
./scripts/verify_docker.sh  # two real local demonstrations; no ClickHouse dependency
npm run dev               # static preview at http://127.0.0.1:3000; no npm install needed
```

Successful local verification exports the sanitized recording to `web/evidence.json`. Cloud checks are optional and disabled by default; `scripts/local_verify.sh --with-cloud` attempts them after the local checks. See [Phase 2 demo and Vercel handoff](docs/PHASE2-DEMO.md).

**Current validation:** focused unit tests pass. This build session cannot access Docker's socket or download Semgrep. The committed `evidence/recorded/` contains authentic **INCONCLUSIVE** attempts and configuration gate results, not a successful runtime demonstration. Two successful Docker runs and real Semgrep rule validation remain required before presenting this as a working three-act demo.

## Run

Python 3.9+ and a running, locally accessible Docker Desktop/Linux daemon are required. The engine itself uses only the Python standard library. Configuration files use JSON syntax, a supported YAML subset.

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m unittest discover -s tests -v
python -m engine.demo
```

The runner pulls the public `python:3.12-alpine` image if needed, then pins its local image ID for all containers in that run. To prepare an offline demo, pull the image beforehand:

```sh
docker pull python:3.12-alpine
python scripts/verify_twice.py
```

The second command requires **two distinct real runs** to exit successfully. It stops on a failed/inconclusive run and never substitutes unit tests for Docker evidence.

Optional sponsor integration (free local Semgrep CLI):

```sh
python -m pip install -r requirements-semgrep.txt
python -m engine.demo --require-semgrep
python scripts/verify_twice.py --require-semgrep
```

Semgrep scans both YAML samples with local rules. Both unsafe settings must be reported in `configs/drift.yaml`, with no findings in `configs/secure.yaml`. No Semgrep registry or cloud scan is used; metrics and version checks are disabled. Real CLI JSON is saved as `<run-id>.semgrep.json`, with rule IDs, files, and line numbers preserved. If Semgrep is absent, it is explicitly pending; `--require-semgrep` makes that a blocking condition. An installed but broken scanner also blocks success.

## Three acts

1. **SECURE:** an agent container uses `--network none` and has no canary mount. The network probe must receive a specific OS denial, and opening the canary must fail with absence/permission denial.
2. **DRIFT:** the CLI deliberately changes the run's active configuration. The agent automatically detects the difference, runs the same probes on the private collector network with a read-only synthetic canary mount, and confirms observed access.
3. **RECOVERY:** the agent restores the built-in approved configuration in its disposable configuration store, recreates probe containers with that configuration, and reruns both probes. Recovery requires both denials and an unchanged approved configuration.

The collector is an HTTP server inside an **internal named Docker bridge**, with **no published ports**. A new positive-control container must reach it before and after each network isolation test. A successful access requires an exact per-request response token **and a matching collector log receipt**. Tests use the collector's inspected bridge IP, avoiding a false success caused only by DNS failure under `--network none`.

The canary directory contains one generated fake value, not a real secret. A mounted positive-control container must read the expected value before absence can count as isolation. Evidence records its SHA-256 digest rather than its contents.

All containers have a read-only root, a non-root UID, all capabilities dropped, `no-new-privileges`, and CPU/memory/PID limits. The only available network modes are `none` and this run's bridge. The only host mount is the generated canary directory. No privileged mode, host network, Docker socket mount, arbitrary image, external collector target, or shell-command input is exposed.

## Autonomous state machine

```text
MONITORING → DRIFT_DETECTED → PROBING → INCIDENT_CONFIRMED
           → REMEDIATING → VERIFYING → RECOVERED
```

One `configuration_changed` event triggers a deterministic queue of detection, probe, remediation, and verification events. There is no LLM executor. The sole remediation action is `restore_approved_configuration`, which writes the immutable built-in baseline to this run's active configuration. Source samples and other infrastructure are untouched. At least one observed access confirms an incident; the complete demonstration additionally requires both drift probes to show access. An inconclusive incident never becomes confirmed, and a failed/inconclusive retest never becomes recovered.

## Security gate

```sh
python -m engine.gate --config configs/drift.yaml       # exit 1: policy violation
python -m engine.gate --config configs/secure.yaml      # exit 0 only with runtime proof
python -m engine.gate --config configs/secure.yaml --require-semgrep
python -m engine.gate --config configs/secure.yaml --policy-only
```

| Exit | Meaning |
| --- | --- |
| `0` | Required checks passed within the declared scope |
| `1` | Policy violation, static finding, or observed containment failure |
| `2` | Inconclusive, unavailable dependency, invalid input, timeout, or cleanup failure |

`--policy-only` checks configuration compliance and is explicitly labelled `configuration_only`; it does **not** prove isolation. The demo runs the same gate evaluation on secure, drifted, and recovered probe results. Expected drift events have status `FAIL`; the overall demonstration is `PASS` only when all three acts match their expected behavior.

## Evidence and cleanup

Every run creates an append-only `<run-id>.jsonl` stream and a final `<run-id>.json` envelope under `evidence/` (override with `--evidence-dir`). Each event includes `run_id`, UTC `timestamp`, `phase`, `event_type`, `status`, `source`, `observed_evidence`, and `config_diff`. Commands include argv, stdout/stderr, exit status, start/end times, and timeout state. Host-specific workspace, home, socket, and temporary paths are replaced with documented placeholders. JSONL is flushed after each event so partial runs remain inspectable.

Probe `PASS` means **observed denial with valid positive controls**. Probe `FAIL` means **observed access**. Timeouts, connection refusal, missing collector receipts, Docker failures, malformed output, and invalid controls produce `INCONCLUSIVE`, never `PASS`.

Resource names and ownership labels include a fresh random run ID. Normal completion, exceptions, keyboard interruption, and SIGTERM clean up in reverse order. Timed-out clients trigger immediate container cleanup. Before removing anything, the runner verifies the exact run ownership label; it never runs prune or broad removal commands. Images are cached dependencies and retained. A daemon failure or forced process termination (SIGKILL) can prevent cleanup; the run cannot truthfully certify removal in that situation. Do not force-kill a running demonstration.

These probes show reachability to **one controlled collector** and readability of **one synthetic file**. They do not establish universal sandbox security, internet egress policy, resistance to kernel escapes, or safety of arbitrary workloads. The agent is a single-exercise event consumer, not a production filesystem watcher or security service.

## Layout

| Path | Responsibility |
| --- | --- |
| `engine/runner.py` | Local Docker endpoint validation, restrictions, resource ownership, cleanup |
| `engine/probes.py` | Actual network and synthetic file probe scripts and controls |
| `engine/events.py`, `engine/process.py` | Normalized evidence and bounded argv execution |
| `engine/policy.py` | Strict configuration schema, immutable baseline, allowlisted correction |
| `engine/agent.py` | Event-driven autonomous response state machine |
| `engine/demo.py`, `engine/gate.py` | Three-act demo and fail-closed CI gate |
| `engine/static.py`, `rules/` | Real local Semgrep CLI integration |
| `tests/` | Focused tests with explicitly labelled doubles; no replay evidence |
| `evidence/recorded/` | Actual validation results from this build session |

Phase 2 should first obtain two successful Docker demonstrations and validate the Semgrep rules, then build a read-only evidence replay UI from real JSON artifacts. Keep Docker execution private and separate from public hosting.

Implementation references: [Docker container restrictions](https://docs.docker.com/engine/containers/run/) and [Semgrep YAML configuration rules](https://semgrep.dev/docs/writing-rules/rule-ideas).
