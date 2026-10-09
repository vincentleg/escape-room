"""Incident commander: detect, investigate, decide, contain, verify, prevent, report.

Runs one controlled scenario in disposable Docker. Remediation is bounded by
decision.MAX_REMEDIATION_ATTEMPTS and every action passes the policy allowlist.
"""

import argparse
import json
import os
import shutil
import tempfile
from pathlib import Path

from .decision import FIELD_BOUNDARY, MAX_REMEDIATION_ATTEMPTS, assess, fingerprint
from .events import FAIL, INCONCLUSIVE, PASS, ROOT, EventLog
from .gate import EXIT_CODES
from .policy import (APPROVED, DRIFT_PATH, AdmissionRejected, HumanApprovalRequired,
                     diff, load_config)
from .probes import Probes
from .process import execute, run_cli
from .runner import InfrastructureError, Runner

EVIDENCE = ROOT / "evidence/commander"
SCENARIOS = {
    "standard": {"override": None, "repeat": False},
    "persistent": {"override": ("run", {"network": "collector"}), "repeat": False},
    "escalation": {"override": ("external", {"network": "collector"}), "repeat": False},
    "recurrence": {"override": None, "repeat": True},
}


def controls_ok(probe_set):
    n, s = probe_set.network.evidence, probe_set.secret.evidence
    return bool(n.get("positive_control_before") and n.get("positive_control_after")
                and s.get("positive_control"))


def observe(log, store, probes, phase):
    result = probes.run(store.read(), phase)
    return result, {"probes": result.statuses(), "controls_ok": controls_ok(result),
                    "active_diff": diff(store.active()), "effective_diff": diff(store.read()),
                    "override": store.override()}


def semgrep_regression(log, changes):
    """Generate a rule from the observed drift; prove it flags drift and spares baseline."""
    cli = shutil.which("semgrep") or (str(ROOT / ".venv/bin/semgrep")
                                      if (ROOT / ".venv/bin/semgrep").is_file() else None)
    rules = [{"id": "escape-room-regression-" + key.replace("_", "-"), "languages": ["yaml"],
              "severity": "ERROR",
              "message": f"Re-introduces incident drift: {key} must be {APPROVED.to_dict()[key]!r}.",
              "pattern": f"{key}: {json.dumps(change['observed'])}"}
             for key, change in sorted(changes.items())]
    text = "rules:\n" + "".join(
        f"  - id: {r['id']}\n    languages: [yaml]\n    severity: ERROR\n"
        f"    message: {json.dumps(r['message'])}\n    pattern: |\n      {r['pattern']}\n" for r in rules)
    result = {"rule_yaml": text, "rule_ids": [r["id"] for r in rules], "status": INCONCLUSIVE}
    if not cli:
        log.emit("PREVENT", "regression_rule_unverified", INCONCLUSIVE, "semgrep",
                 {"reason": "Semgrep CLI unavailable"})
        return result
    with tempfile.TemporaryDirectory(prefix="escape-regression-") as tmp:
        log.redact_path(tmp, "<regression-temp>")
        tmp = Path(tmp)
        (tmp / "rule.yaml").write_text(text)
        (tmp / "incident.yaml").write_text(json.dumps(
            {**APPROVED.to_dict(), **{k: c["observed"] for k, c in changes.items()}}, indent=2) + "\n")
        (tmp / "baseline.yaml").write_text(json.dumps(APPROVED.to_dict(), indent=2) + "\n")
        env = {**os.environ, "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0",
               "SEMGREP_SETTINGS_FILE": str(tmp / "settings.yml"), "SEMGREP_LOG_FILE": str(tmp / "s.log")}
        run = execute([cli, "scan", "--config", "rule.yaml", "--json", "--metrics", "off",
                       "--disable-version-check", "--no-git-ignore", "--strict",
                       "incident.yaml", "baseline.yaml"], timeout=120, env=env, cwd=str(tmp))
    try:
        document = json.loads(run.stdout)
        hits = [(Path(f["path"]).name, f["check_id"].split(".")[-1]) for f in document["results"]]
        flagged = {rid for name, rid in hits if name == "incident.yaml"}
        false_pos = [h for h in hits if h[0] == "baseline.yaml"]
        ok = not document.get("errors") and flagged == set(result["rule_ids"]) and not false_pos
    except (ValueError, KeyError, TypeError):
        ok, flagged, false_pos = False, set(), []
    result.update(status=PASS if ok else FAIL, detected_on_incident=sorted(flagged),
                  false_positives_on_baseline=len(false_pos))
    log.emit("PREVENT", "regression_rule_verified", result["status"], "semgrep",
             {k: v for k, v in result.items() if k != "rule_yaml"})
    return result


def prior_fingerprints():
    seen = []
    for path in sorted(EVIDENCE.glob("*.json")):
        try:
            summary = json.loads(path.read_text())["summary"]
            seen.append({"run_id": path.stem, "fingerprint": summary["fingerprint"],
                         "recorded_at": summary.get("finished_at")})
        except (ValueError, KeyError):
            continue
    return seen


def scenario(log, runner, name):
    spec = SCENARIOS[name]
    runner.setup()
    store, probes = runner.store, Probes(runner, log)
    _, secure = observe(log, store, probes, "SECURE")
    if secure["probes"] != {"network": PASS, "secret": PASS}:
        return INCONCLUSIVE, {"reason": "Baseline containment not verified"}
    drift = load_config(DRIFT_PATH)
    store.inject_drift(drift)
    if spec["override"]:
        owner, fields = spec["override"]
        store.inject_override(fields, owner)
    log.emit("DETECT", "drift_detected", FAIL, "policy",
             {"synthetic_exercise": True, "override_owner": spec["override"][0] if spec["override"] else None},
             config_diff=diff(store.read()))
    initial_changes = diff(store.read())
    _, obs = observe(log, store, probes, "DRIFT")
    decisions, history = [], []
    outcome = None
    for _ in range(MAX_REMEDIATION_ATTEMPTS + 1):
        decision = assess(obs["probes"], obs["controls_ok"], obs["active_diff"],
                          obs["effective_diff"], obs["override"], history)
        decisions.append(decision)
        log.emit("DECIDE", "incident_decision", PASS if decision["outcome"] == "VERIFIED_SAFE"
                 else FAIL if decision["outcome"] == "ESCALATED" else PASS, "decision_engine", decision)
        if decision["outcome"] in ("VERIFIED_SAFE", "ESCALATED"):
            outcome = decision["outcome"]
            break
        action = decision["selected_action"]
        try:
            store.remediate(action)
            history.append({"action": action, "executed": True})
            log.emit("CONTAIN", "remediation_executed", PASS, "policy",
                     {"action": action, "scope": "disposable run configuration"})
        except HumanApprovalRequired as exc:  # Defence in depth: assess() should never select this.
            log.emit("CONTAIN", "remediation_blocked", FAIL, "policy", {"action": action, "reason": str(exc)})
            outcome = "ESCALATED"
            break
        _, obs = observe(log, store, probes, "VERIFY-%d" % len(history))
    outcome = outcome or "ESCALATED"

    boundaries = sorted({FIELD_BOUNDARY[k] for k in initial_changes})
    root_chain = [d["root_cause"] for d in decisions if d.get("root_cause")]
    fp = fingerprint(boundaries, initial_changes, root_chain)
    prior = [p for p in prior_fingerprints() if p["fingerprint"] == fp]
    prevention = []
    recurrence = None
    if outcome == "VERIFIED_SAFE":
        guarded = store.enable_guard(initial_changes)
        refused = not store.admits(drift)
        log.emit("PREVENT", "admission_guard_enabled", PASS if refused else FAIL, "policy",
                 {"guarded_values": guarded, "rejects_original_drift": refused})
        prevention.append({"status": "APPLIED" if refused else "FAILED",
                           "action": "Run-scoped admission guard",
                           "detail": "Refuses any write that sets " + ", ".join(
                               f"{k}={json.dumps(v)}" for k, v in sorted(guarded.items())),
                           "verified": "Original drift checked against guard: " + ("rejected" if refused else "ACCEPTED")})
        if spec["repeat"]:
            try:
                store.inject_drift(drift)
                blocked = False
            except AdmissionRejected:
                blocked = True
            log.emit("RECURRENCE", "repeat_drift_attempt", PASS if blocked else FAIL, "policy",
                     {"identical_fingerprint": fp, "blocked_by_guard": blocked})
            _, post = observe(log, store, probes, "RECURRENCE")
            contained = post["probes"] == {"network": PASS, "secret": PASS} and not post["effective_diff"]
            recurrence = {"blocked_by_guard": blocked, "probes_after": post["probes"],
                          "still_contained": contained}
            if not (blocked and contained):
                outcome = "ESCALATED"
    regression = semgrep_regression(log, initial_changes)
    prevention.append({"status": "RECOMMENDED" if regression["status"] == PASS else "UNVERIFIED",
                       "action": "Semgrep regression rule for CI",
                       "detail": f"{len(regression['rule_ids'])} rule(s) generated from the observed drift",
                       "verified": (f"Flags incident config ({len(regression.get('detected_on_incident', []))}"
                                    f"/{len(regression['rule_ids'])} rules), "
                                    f"{regression.get('false_positives_on_baseline', '?')} false positives on baseline")
                       if regression["status"] != INCONCLUSIVE else "Semgrep unavailable"})
    prevention.append({"status": "BLOCKED", "action": "Commit rule to repository CI / org policy",
                       "detail": "Changes shared policy outside the disposable run",
                       "verified": "Requires human approval; not attempted"})
    if outcome == "ESCALATED" and obs.get("override"):
        prevention.append({"status": "BLOCKED", "action": "Remove externally owned override",
                           "detail": "Override owner is outside this run",
                           "verified": "Requires human approval; layer left in place, evidence preserved"})
    final = "RECURRENCE_BLOCKED" if (recurrence and outcome == "VERIFIED_SAFE") else outcome
    log.emit("REPORT", "incident_outcome", PASS if outcome == "VERIFIED_SAFE" else FAIL, "agent",
             {"outcome": final, "fingerprint": fp, "prior_matches": len(prior)})
    return (PASS if outcome == "VERIFIED_SAFE" else FAIL), {
        "scenario": name, "outcome": final, "fingerprint": fp, "decisions": decisions,
        "attempts": history, "max_attempts": MAX_REMEDIATION_ATTEMPTS,
        "boundaries": boundaries, "root_cause_chain": root_chain, "initial_drift": initial_changes,
        "prior_matches": prior, "recurrence": recurrence, "prevention": prevention,
        "regression_rule": regression["rule_yaml"], "regression_status": regression["status"],
        "final_probes": obs["probes"]}


STEP = {"DETECT": "DETECT", "DRIFT": "INVESTIGATE", "DECIDE": "DECIDE", "CONTAIN": "CONTAIN",
        "PREVENT": "PREVENT", "RECURRENCE": "PREVENT", "REPORT": "REPORT"}


def public_run(path):
    """Narrow, sanitized projection of one recorded commander run for the static site."""
    import hashlib
    raw = Path(path).read_bytes()
    document = json.loads(raw)
    s, events = document["summary"], document["events"]
    start = events[0]["timestamp"]
    timeline = []
    for index, e in enumerate(events):
        step = "VERIFY" if e["phase"].startswith("VERIFY") else STEP.get(e["phase"])
        if step and e["event_type"] in ("drift_detected", "probe_set_completed", "incident_decision",
                                        "remediation_executed", "admission_guard_enabled",
                                        "repeat_drift_attempt", "regression_rule_verified",
                                        "incident_outcome"):
            ev = e["observed_evidence"]
            label = {"drift_detected": lambda: "Drift in " + ", ".join(sorted(e["config_diff"])),
                     "probe_set_completed": lambda: f"Probes: network {ev['network']}, canary {ev['secret']}",
                     "incident_decision": lambda: f"Decision #{ev['attempt']}: {ev['outcome']}"
                     + (f" → {ev['selected_action']}" if ev.get("selected_action") else ""),
                     "remediation_executed": lambda: "Executed " + ev["action"],
                     "admission_guard_enabled": lambda: "Guard applied; original drift "
                     + ("rejected" if ev["rejects_original_drift"] else "accepted"),
                     "repeat_drift_attempt": lambda: "Repeat drift " + ("BLOCKED by guard" if ev["blocked_by_guard"] else "accepted"),
                     "regression_rule_verified": lambda: "Semgrep regression rule " + e["status"],
                     "incident_outcome": lambda: "Outcome: " + ev["outcome"]}[e["event_type"]]()
            timeline.append({"step": step, "label": label, "status": e["status"], "event_index": index,
                             "t": e["timestamp"]})
    keep = ("attempt", "facts", "boundaries_violated", "evidence_confidence", "severity", "classification",
            "root_cause", "root_cause_evidence", "candidates", "selected_action", "outcome", "rationale",
            "verification_criteria", "blocked_actions")
    return {"run_id": document["run_id"], "source_sha256": hashlib.sha256(raw).hexdigest(),
            "scenario": s["scenario"], "status": document["status"], "outcome": s["outcome"],
            "recorded_at": start, "finished_at": s["finished_at"], "event_count": len(events),
            "cleanup_complete": s["cleanup_complete"], "fingerprint": s["fingerprint"],
            "prior_matches": [{"run_id": p["run_id"], "recorded_at": p["recorded_at"]} for p in s["prior_matches"]],
            "root_cause_chain": s["root_cause_chain"], "boundaries": s["boundaries"],
            "attempts": s["attempts"], "max_attempts": s["max_attempts"], "final_probes": s["final_probes"],
            "decisions": [{k: d[k] for k in keep if k in d} for d in s["decisions"]],
            "prevention": s["prevention"], "recurrence": s["recurrence"],
            "regression_rule": s["regression_rule"], "regression_status": s["regression_status"],
            "timeline": timeline}


def export(destination=ROOT / "web/commander.json"):
    runs = [public_run(p) for p in EVIDENCE.glob("*.json")]
    latest = {}
    for run in sorted(runs, key=lambda r: r["recorded_at"]):
        if run["cleanup_complete"]:
            latest[run["scenario"]] = run
    Path(destination).write_text(json.dumps(
        {"schema_version": 1, "mode": "recorded_local_docker",
         "scenarios": [latest[k] for k in SCENARIOS if k in latest]}, indent=2) + "\n")
    return destination


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=sorted(SCENARIOS) + ["export"])
    args = parser.parse_args(argv)
    if args.scenario == "export":
        print(export())
        return 0
    log = EventLog(EVIDENCE)
    status, summary, runner = INCONCLUSIVE, {"scenario": args.scenario}, None
    try:
        with Runner(log) as runner:
            status, details = scenario(log, runner, args.scenario)
            summary.update(details)
    except (InfrastructureError, ValueError, OSError) as exc:
        log.emit("SETUP", "execution_error", INCONCLUSIVE, "engine", {"reason": str(exc)})
        status, summary["reason"] = INCONCLUSIVE, str(exc)
    summary["cleanup_complete"] = bool(runner and runner.cleanup_ok)
    if not summary["cleanup_complete"]:
        status = INCONCLUSIVE
    summary["finished_at"] = log.events[-1]["timestamp"]
    log.finish(status, **summary)
    print(json.dumps({"scenario": args.scenario, "status": status,
                      "outcome": summary.get("outcome"), "run_id": log.run_id}))
    return EXIT_CODES[status]


if __name__ == "__main__":
    raise SystemExit(run_cli(main))
