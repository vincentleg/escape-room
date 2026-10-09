#!/bin/bash
# Run from normal macOS Terminal. Syntax checks must not execute this script.
set +x
set -euo pipefail
umask 077

ESCAPE_VERIFY_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd -- "$ESCAPE_VERIFY_ROOT"
if [[ ! -f .venv/bin/activate || ! -x .venv/bin/python ]]; then
  printf '%s\n' 'INCONCLUSIVE: Existing .venv is missing or unusable.'
  exit 2
fi
# Deliberately do not source .env.clickhouse or export its credentials.
source .venv/bin/activate
exec "$ESCAPE_VERIFY_ROOT/.venv/bin/python" -B - "$@" <<'PY'
import argparse
import contextlib
import http.client
import io
import json
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from engine import demo
from engine.clickhouse import ClickHouseError, Client, Settings
from engine.events import EventLog, FAIL, INCONCLUSIVE, PASS, ROOT
from engine.process import docker_env
from engine.static import Scan, verify_samples
from engine.telemetry import upload


class Blocked(Exception):
    def __init__(self, status, reason):
        self.status, self.reason = status, reason


class StepTimeout(Exception):
    pass


def alarm(signum, frame):
    raise StepTimeout()


def interrupt(signum, frame):
    # Unwind the engine's context managers, including its Docker cleanup.
    raise KeyboardInterrupt()


def command(argv, timeout=20, env=None):
    # Never echo subprocess output: dependency tools can include sensitive values.
    return subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, timeout=timeout, env=env, check=False)


def require(condition, reason, status=INCONCLUSIVE):
    if not condition:
        raise Blocked(status, reason)


def main():
    parser = argparse.ArgumentParser(description="Local Docker verification; cloud telemetry is opt-in.")
    parser.add_argument("--local-only", action="store_true", help="Run without any ClickHouse connection.")
    parser.add_argument("--with-cloud", action="store_true", help="Attempt optional cloud checks after local verification.")
    args = parser.parse_args()
    cloud_enabled = args.with_cloud and not args.local_only
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    directory = ROOT / "evidence/local-verify" / (stamp + "-" + uuid.uuid4().hex[:12])
    directory.mkdir(parents=True, mode=0o700)
    log = EventLog(directory, echo=False)
    labels = ["Existing virtualenv", "Docker Desktop connectivity",
              "ClickHouse DNS and verified HTTPS", "ClickHouse SELECT 1",
              "Semgrep CLI", "Containment demonstration 1",
              "Containment demonstration 2", "Custom Semgrep rules",
              "ClickHouse upload and event readback"]
    checks = [{"check": label, "status": INCONCLUSIVE, "reason": "Not run"}
              for label in labels]
    active = 0
    settings = None
    client = None
    artifacts = []

    def step(index, action, seconds):
        nonlocal active
        active = index
        print("[%d/%d] %s..." % (index + 1, len(checks), labels[index]), flush=True)
        signal.setitimer(signal.ITIMER_REAL, seconds)
        try:
            # Existing engine modules may print event JSON. Keep it in artifacts,
            # never on the terminal (including synthetic collector request tokens).
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                observed = action()
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
        checks[index].update(status=PASS, reason="Verified")
        log.emit("LOCAL_VERIFY", "check_completed", PASS, "local_verify",
                 {"check": labels[index], **(observed or {})})

    def optional_step(index, action, seconds):
        try:
            step(index, action, seconds)
            return True
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            optional_status = exc.status if isinstance(exc, Blocked) else INCONCLUSIVE
            optional_reason = exc.reason if isinstance(exc, Blocked) else "Optional check unavailable; local verification continues."
            checks[index].update(status=optional_status, reason=optional_reason)
            log.emit("LOCAL_VERIFY", "optional_check_unavailable", optional_status, "local_verify",
                     {"check": labels[index], "reason": optional_reason})
            return False

    def virtualenv():
        require(Path(sys.prefix).resolve() == (ROOT / ".venv").resolve(),
                "The existing project virtualenv was not activated.")
        return {"project_virtualenv": True}

    def docker():
        require(shutil.which("docker") is not None, "Docker CLI is missing; install/open Docker Desktop.")
        endpoint = os.environ.get("DOCKER_HOST")
        context = os.environ.get("DOCKER_CONTEXT")
        if context or not endpoint:
            args = ["docker", "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"]
            if context:
                args.append(context)
            result = command(args, env=docker_env())
            require(result.returncode == 0, "Cannot inspect the selected Docker context.")
            try:
                endpoint = json.loads(result.stdout)
            except ValueError:
                raise Blocked(INCONCLUSIVE, "Docker context returned invalid output.") from None
        require(isinstance(endpoint, str) and endpoint.startswith("unix:///"),
                "Select an existing local Docker Desktop Unix-socket context; remote daemons are refused.")
        result = command(["docker", "--host", endpoint, "version", "--format", "{{json .Server}}"],
                         env=docker_env())
        require(result.returncode == 0, "Docker Desktop is not reachable. Open Docker Desktop and rerun.")
        try:
            server = json.loads(result.stdout)
        except ValueError:
            raise Blocked(INCONCLUSIVE, "Docker returned invalid server information.") from None
        require(isinstance(server, dict) and server.get("Os") == "linux",
                "A reachable local Docker Linux engine is required.")
        return {"daemon_connected": True, "server_os": "linux", "exit_status": result.returncode}

    def clickhouse_network():
        nonlocal settings, client
        try:
            settings = Settings.load()
        except (ClickHouseError, OSError, ValueError):
            raise Blocked(INCONCLUSIVE, "Private .env.clickhouse is missing, incomplete, or invalid.") from None
        require(settings.secure, "ClickHouse Cloud verification requires HTTPS with certificate validation.")
        log.redact_path(settings.password, "<redacted>")
        addresses = socket.getaddrinfo(settings.host, settings.port, type=socket.SOCK_STREAM)
        require(bool(addresses), "ClickHouse DNS lookup returned no addresses.")
        connection = http.client.HTTPSConnection(settings.host, settings.port, timeout=10,
                                                 context=ssl.create_default_context())
        try:
            # No credentials here. An authentication challenge still proves HTTPS
            # reachability; the next stage separately verifies credentials.
            connection.request("GET", "/ping")
            response = connection.getresponse()
            code = response.status
            response.read(1024)
            require(code in (200, 401, 403), "ClickHouse HTTPS endpoint returned an unexpected status.")
        finally:
            connection.close()
        client = Client(settings)
        return {"dns_resolved": True, "tls_certificate_verified": True, "http_status": code}

    def select_one():
        try:
            return client.select_one()
        except ClickHouseError as exc:
            if re.search(r"status (401|403)\b", str(exc)):
                raise Blocked(FAIL, "ClickHouse rejected SELECT 1 (HTTP 401/403); check credentials/access policy.") from None
            raise Blocked(INCONCLUSIVE, "ClickHouse SELECT 1 did not succeed; no credentials were printed.") from None

    def semgrep():
        cli = shutil.which("semgrep")
        installed = False
        if not cli:
            result = command([sys.executable, "-m", "pip", "install", "--disable-pip-version-check",
                              "--no-input", "--no-cache-dir", "--retries", "0", "--timeout", "15",
                              "-r", str(ROOT / "requirements-semgrep.txt")], timeout=240)
            log.emit("LOCAL_VERIFY", "semgrep_installation", PASS if result.returncode == 0 else INCONCLUSIVE,
                     "pip", {"exit_status": result.returncode, "scope": "existing_project_virtualenv",
                             "requirements": "requirements-semgrep.txt", "raw_output_withheld": True})
            require(result.returncode == 0, "Semgrep installation failed; package access or Python compatibility is blocking.")
            installed = True
            cli = shutil.which("semgrep")
        require(cli is not None, "Semgrep executable is unavailable after installation.")
        env = {**os.environ, "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0",
               "SEMGREP_SETTINGS_FILE": str(directory / "semgrep-settings.yml"),
               "SEMGREP_LOG_FILE": str(directory / "semgrep-version.log")}
        result = command([cli, "--version"], env=env)
        require(result.returncode == 0, "Semgrep is installed but cannot run.")
        # Do not echo untrusted tool output or inherited environment values.
        version = result.stdout.strip()
        require(re.fullmatch(r"\d+\.\d+\.\d+(?:[a-zA-Z0-9.+-]*)?", version) is not None,
                "Semgrep returned an unrecognized version response.")
        return {"version": version, "installed_in_this_run": installed, "exit_status": 0}

    def run_demo(number):
        run_directory = directory / ("demo-%d" % number)
        # In-process execution preserves the engine's exception/Ctrl-C cleanup.
        # Each invocation creates fresh containers, labels, network and run ID.
        exit_code = demo.main(["--evidence-dir", str(run_directory)])
        candidates = [p for p in run_directory.glob("*.json") if not p.name.endswith(".semgrep.json")]
        require(len(candidates) == 1, "The demonstration did not produce exactly one final artifact.")
        path = candidates[0]
        document = json.loads(path.read_text())
        summary = document.get("summary", {})
        expected = {"secure": {"network": PASS, "secret": PASS},
                    "drift": {"network": FAIL, "secret": FAIL},
                    "recovered": {"network": PASS, "secret": PASS}}
        valid = (summary.get("three_acts_verified") is True
                 and summary.get("cleanup_complete") is True
                 and summary.get("agent_state") == "RECOVERED"
                 and summary.get("drift_gate_exit") == 1 and summary.get("recovered_gate_exit") == 0
                 and all(summary.get(key) == value for key, value in expected.items()))
        require(valid, "Demonstration evidence does not establish all three acts, gates, and cleanup.",
                FAIL if exit_code == 1 else INCONCLUSIVE)
        require(document["run_id"] not in {d["run_id"] for _, d in artifacts},
                "Demonstration run IDs are not distinct.")
        artifacts.append((path, document))
        return {"demonstration": number, "artifact": str(path.relative_to(ROOT)),
                "exit_status": exit_code, "three_acts_verified": True, "cleanup_complete": True}

    def rules():
        # Both demos already invoked the real CLI. Verify their saved raw JSON;
        # do not rerun a scan or manufacture findings to fill this report.
        require(len(artifacts) == 2, "Two real demonstrations are required before rule verification.")
        for path, document in artifacts:
            raw_path = path.with_name(document["run_id"] + ".semgrep.json")
            require(raw_path.is_file(), "Actual Semgrep JSON output is missing.")
            raw = json.loads(raw_path.read_text())
            findings = raw.get("results")
            require(isinstance(findings, list) and not raw.get("errors"), "Semgrep JSON contains errors or no result array.")
            scanned = {str((ROOT / p).resolve()) for p in raw.get("paths", {}).get("scanned", [])}
            require({str(ROOT / "configs/secure.yaml"), str(ROOT / "configs/drift.yaml")} <= scanned,
                    "Semgrep did not scan both configuration samples.")
            require(all(isinstance(f.get("start", {}).get("line"), int)
                        and f["start"]["line"] > 0 for f in findings),
                    "Semgrep findings do not include actual source line numbers.")
            require(verify_samples(log, Scan(True, FAIL if findings else PASS, findings)) == PASS,
                    "Custom rules must flag both unsafe settings and leave the secure sample clean.", FAIL)
        return {"actual_scan_artifacts_verified": 2, "secure_sample_clean": True,
                "required_rules": ["escape-room-collector-network", "escape-room-canary-mount"]}

    def telemetry():
        # Only this invocation's two authenticated runtime artifacts are uploaded.
        # The existing uploader creates at most its table in the existing database;
        # it never provisions a service, cloud instance, or additional database.
        verified = [upload(client, path, log) for path, _ in artifacts]
        require(len(verified) == 2 and all(item["events_verified"] > 0 for item in verified),
                "Both runs must have exact event-ID readback from ClickHouse.")
        return {"runs_verified": 2, "events_verified": sum(item["events_verified"] for item in verified)}

    status, reason = INCONCLUSIVE, "Verification did not complete."
    signal.signal(signal.SIGALRM, alarm)
    signal.signal(signal.SIGTERM, interrupt)
    try:
        step(0, virtualenv, 5)
        step(1, docker, 45)
        # Static-tool installation and optional cloud access must never suppress
        # the independent real Docker exercise. Their own statuses stay honest.
        optional_step(4, semgrep, 270)
        step(5, lambda: run_demo(1), 600)
        step(6, lambda: run_demo(2), 600)
        optional_step(7, rules, 10)
        from engine.replay import export_replay
        exported = export_replay([path for path, _ in artifacts])
        log.emit("LOCAL_VERIFY", "public_replay_exported", PASS, "replay",
                 {"runs": len(artifacts), "destination": "web/evidence.json", "sanitized": True})
        if cloud_enabled:
            if optional_step(2, clickhouse_network, 15) and optional_step(3, select_one, 25):
                optional_step(8, telemetry, 180)
        else:
            for index in (2, 3, 8):
                checks[index]["reason"] = "Optional cloud check disabled; no connection attempted"
        local_statuses = {checks[i]["status"] for i in (0, 1, 4, 5, 6, 7)}
        status = FAIL if FAIL in local_statuses else PASS if local_statuses == {PASS} else INCONCLUSIVE
        reason = ("Two genuine Docker demonstrations verified; public replay exported. "
                  + ("Semgrep verified." if checks[7]["status"] == PASS else "Semgrep remains unverified."))
    except Blocked as exc:
        status, reason = exc.status, exc.reason
    except (StepTimeout, subprocess.TimeoutExpired):
        reason = "Check timed out; no success is inferred."
    except socket.gaierror:
        reason = "ClickHouse DNS resolution failed."
    except ssl.SSLError:
        reason = "ClickHouse TLS verification/connection failed; certificate checks remain enabled."
    except ClickHouseError:
        reason = "ClickHouse operation or exact event readback failed; ingestion is unverified."
    except KeyboardInterrupt:
        reason = "Verification interrupted; remaining checks were not run."
    except Exception:
        # Never print traceback/exception content that could include credentials.
        reason = "Local verification encountered an error; remaining checks were not run."
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    if status != PASS and checks[active]["reason"] == "Not run":
        checks[active].update(status=status, reason=reason)
        log.emit("LOCAL_VERIFY", "check_blocked", status, "local_verify",
                 {"check": labels[active], "reason": reason})
    report = {"status": status, "scope": "local_containment_and_static_checks",
              "cloud_optional": True, "checks": checks, "reason": reason,
              "exit_code": {PASS: 0, FAIL: 1, INCONCLUSIVE: 2}[status]}
    log.finish(status, checks=checks, reason=reason, exit_code=report["exit_code"])
    with (directory / "report.json").open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print("\nESCAPE ROOM LOCAL VERIFICATION: " + status)
    for check in checks:
        cloud_check = check["check"] in (labels[2], labels[3], labels[8])
        suffix = " (optional; skipped)" if cloud_check and not cloud_enabled else " (optional)" if cloud_check else " (not run)" if check["reason"] == "Not run" else ""
        print("  %-12s %s%s" % (check["status"], check["check"], suffix))
    print(reason)
    print("Evidence: " + str(directory.relative_to(ROOT)))
    if len(artifacts) == 2:
        print("Public replay: web/evidence.json — rebuild/redeploy the static site to publish it.")
    return report["exit_code"]


try:
    sys.exit(main())
except Exception:
    # Also keep early filesystem/import-adjacent failures credential-safe.
    print("INCONCLUSIVE: Could not finalize local verification; private evidence may be incomplete.")
    sys.exit(2)
PY
