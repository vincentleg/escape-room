"""Export an allowlisted public replay from authentic local engine artifacts."""

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from .events import ROOT
from .telemetry import load_artifact

STATES = ["SECURE", "DRIFT_DETECTED", "INCIDENT_CONFIRMED", "REMEDIATING", "VERIFYING", "RECOVERED"]
TRANSITIONS = ["DRIFT_DETECTED", "PROBING", "INCIDENT_CONFIRMED", "REMEDIATING", "VERIFYING", "RECOVERED"]


def require(value, message):
    if not value:
        raise ValueError(message)


def public_run(path):
    path = Path(path)
    load_artifact(path)  # Schema/finalization validation; does not connect to anything.
    raw = path.read_bytes()
    doc = json.loads(raw)
    summary, events = doc["summary"], doc["events"]
    require(summary.get("three_acts_verified") is True and summary.get("cleanup_complete") is True,
            "Replay requires completed containment and cleanup evidence")
    require(summary.get("agent_state") == "RECOVERED" and summary.get("drift_gate_exit") == 1
            and summary.get("recovered_gate_exit") == 0, "Replay requires genuine gate decisions")
    for phase, expected in (("SECURE", "PASS"), ("DRIFT", "FAIL"), ("RECOVERY", "PASS")):
        require(any(e["phase"] == phase and e["event_type"] == "security_gate" and e["status"] == expected
                    and e["observed_evidence"].get("exit_code") == (1 if expected == "FAIL" else 0)
                    for e in events), "Replay requires actual gate events for each act")
    transitions = [(i, e) for i, e in enumerate(events) if e["event_type"] == "state_transition"]
    require([e["observed_evidence"].get("to") for _, e in transitions] == TRANSITIONS,
            "Replay requires the actual ordered state-machine transitions")
    probes = []
    for phase, expected in (("SECURE", "PASS"), ("DRIFT", "FAIL"), ("RECOVERY", "PASS")):
        require(summary.get({"SECURE": "secure", "DRIFT": "drift", "RECOVERY": "recovered"}[phase])
                == {"network": expected, "secret": expected}, "Summary does not match the expected three acts")
        for event_type, name in (("network_probe", "network"), ("synthetic_secret_probe", "secret")):
            matches = [(i, e) for i, e in enumerate(events) if e["phase"] == phase and e["event_type"] == event_type]
            require(len(matches) == 1, "Replay needs exactly one observed probe of each kind per act")
            index, event = matches[0]
            evidence = event["observed_evidence"]
            cmd, observed = evidence.get("command", {}), evidence.get("probe", {})
            exit_status = 10 if expected == "PASS" else 0
            require(event["status"] == expected and cmd.get("exit_status") == exit_status
                    and not cmd.get("timed_out") and not cmd.get("error"), "Probe execution was not verified")
            require(observed.get("outcome") == ("denied" if expected == "PASS" else "access"),
                    "Probe outcome is inconsistent")
            receipt = False
            if name == "network":
                controls = evidence.get("positive_control_before") is True and evidence.get("positive_control_after") is True
                if expected == "PASS":
                    require(controls and observed.get("errno") in (1, 13, 101, 113), "Network denial lacks controls")
                else:
                    token = evidence.get("request_token")
                    receipt = bool(token and observed.get("collector_token") == token
                                   and (evidence.get("collector_receipt") or {}).get("token") == token)
                    require(receipt, "Network access lacks the matching collector receipt")
            else:
                controls = evidence.get("positive_control") is True
                if expected == "PASS":
                    require(controls and observed.get("errno") in (2, 13), "Canary denial lacks a positive control")
                else:
                    require(observed.get("sha256") and observed["sha256"] == evidence.get("expected_sha256")
                            and observed.get("bytes_read", 0) > 0, "Canary access lacks verified content")
            probes.append({"kind": name, "phase": phase, "status": expected,
                           "timestamp": event["timestamp"], "event_index": index,
                           "exit_status": exit_status, "outcome": observed["outcome"],
                           "positive_controls": controls, "collector_receipt": receipt,
                           "errno": observed.get("errno"), "content_verified": name == "secret" and expected == "FAIL"})
    secure = max((p for p in probes if p["phase"] == "SECURE"), key=lambda p: p["event_index"])
    frames = [{"state": "SECURE", "timestamp": secure["timestamp"], "event_index": secure["event_index"]}]
    for index, event in transitions:
        state = event["observed_evidence"]["to"]
        if state in STATES:
            frames.append({"state": state, "timestamp": event["timestamp"], "event_index": index})
    require([f["state"] for f in frames] == STATES and [f["event_index"] for f in frames] == sorted(f["event_index"] for f in frames),
            "Replay frames must follow observed event order")
    ranges = {"SECURE": (-1, frames[0]["event_index"]),
              "DRIFT": (frames[1]["event_index"], frames[2]["event_index"]),
              "RECOVERY": (frames[4]["event_index"], frames[5]["event_index"])}
    require(all(ranges[p["phase"]][0] < p["event_index"] <= ranges[p["phase"]][1] for p in probes),
            "Each probe must occur inside its recorded state interval")
    findings = []
    for event in events:
        if event["event_type"] == "semgrep_finding":
            finding = event["observed_evidence"]
            rule = finding.get("rule_id", "").split(".")[-1]
            source_name = Path(finding.get("file", "")).name
            if rule in ("escape-room-collector-network", "escape-room-canary-mount") and source_name in ("secure.yaml", "drift.yaml"):
                findings.append({"rule_id": rule, "file": "configs/" + source_name,
                                 "line": finding.get("line")})
    run = {"run_id": doc["run_id"], "recorded_at": events[-1]["timestamp"],
            "source_sha256": hashlib.sha256(raw).hexdigest(), "containment_status": "PASS",
            "semgrep_status": summary.get("semgrep", "INCONCLUSIVE"),
            "cleanup_complete": True, "drift_gate_exit": 1, "recovery_gate_exit": 0,
            "frames": frames, "probes": probes, "findings": findings}
    from .integrations import receipts_for
    run["integrations"] = receipts_for(run, events)
    return run


def infrastructure():
    # Only allowlisted statuses; no raw errors, settings, paths or credentials.
    reports = sorted((ROOT / "evidence/local-verify").glob("*/report.json"), key=lambda p: p.stat().st_mtime)
    result = {"docker": "INCONCLUSIVE", "cloud": "INCONCLUSIVE", "semgrep": "INCONCLUSIVE"}
    if reports:
        try:
            report = json.loads(reports[-1].read_text())
            labels = {"Docker Desktop connectivity": "docker", "ClickHouse DNS and verified HTTPS": "cloud",
                      "Custom Semgrep rules": "semgrep"}
            for check in report.get("checks", []):
                if check.get("check") in labels and check.get("status") in ("PASS", "FAIL", "INCONCLUSIVE"):
                    result[labels[check["check"]]] = check["status"]
        except (ValueError, OSError):
            pass
    return result


def export_replay(paths=None, destination=None):
    selected = []
    if paths is not None:
        selected = [public_run(path) for path in paths]
    else:
        for path in (ROOT / "evidence").rglob("*.json"):
            if path.name.endswith(".semgrep.json") or path.name == "report.json":
                continue
            try:
                doc = json.loads(path.read_text())
                if isinstance(doc, dict) and doc.get("summary", {}).get("three_acts_verified") is True:
                    selected.append(public_run(path))
            except (ValueError, KeyError, TypeError, OSError, RuntimeError):
                continue
    selected = sorted({r["run_id"]: r for r in selected}.values(), key=lambda r: r["recorded_at"])[-2:]
    data = {"schema_version": 1, "mode": "recorded" if selected else "awaiting_evidence",
            "generated_at": datetime.now(timezone.utc).isoformat(), "runs": selected,
            "verified_run_count": len(selected), "infrastructure": infrastructure(),
            "cloud_ingestion": "VERIFIED" if selected and all(r["integrations"]["clickhouse"]["status"] == "PASS" for r in selected) else "UNVERIFIED",
            "scope": "Controlled collector reachability and synthetic canary readability only"}
    target = Path(destination or ROOT / "web/evidence.json")
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(data, indent=2) + "\n")
    temporary.replace(target)
    # Keep an already-built local preview current without adding dependencies.
    built = ROOT / "web/dist/evidence.json"
    if destination is None and built.parent.is_dir():
        built.write_text(target.read_text())
    return data


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifacts", nargs="*")
    args = parser.parse_args()
    result = export_replay(args.artifacts or None)
    print("Public replay exported: %d verified local run(s); no cloud connection." % result["verified_run_count"])
