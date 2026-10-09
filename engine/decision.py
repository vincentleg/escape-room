"""Deterministic, explainable incident decisions over observed evidence.

Every field is computed from probe outcomes, configuration diffs and explicit
policy below. No model output can add an action: advice is only compared
against the allowlist.
"""

import hashlib
import json

from .events import FAIL, PASS
from .policy import QUARANTINE_OVERRIDE, RESTORE_APPROVED

MAX_REMEDIATION_ATTEMPTS = 2
BOUNDARY = {"network": "network_egress", "secret": "canary_read"}
FIELD_BOUNDARY = {"network": "network_egress", "mount_canary": "canary_read"}

# Actions an operator might reach for. Only allowlisted ones can ever be selected.
NEVER_AUTONOMOUS = {
    "kill_host_docker_daemon": "Host-level action outside the disposable run scope",
    "delete_canary_and_logs": "Destroys incident evidence",
    "execute_model_suggested_command": "No arbitrary shell; model output is advisory only",
}


def fingerprint(boundaries, changes, root_cause):
    canonical = json.dumps({"boundaries": sorted(boundaries),
                            "drift": {k: v["observed"] for k, v in sorted(changes.items())},
                            "root_cause": root_cause}, sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def assess(probes, controls_ok, active_diff, effective_diff, override, history):
    """Return one decision record. `probes` maps network/secret to PASS/FAIL/INCONCLUSIVE."""
    violated = sorted(BOUNDARY[k] for k, status in probes.items() if status == FAIL)
    unverified = sorted(BOUNDARY[k] for k, status in probes.items() if status not in (PASS, FAIL))
    facts = [f"{BOUNDARY[k]} probe: {'ACCESS OBSERVED' if s == FAIL else 'denied' if s == PASS else 'unverified'}"
             for k, s in sorted(probes.items())]
    facts += [f"effective {k}: {v['observed']!r} (approved {v['approved']!r})"
              for k, v in sorted(effective_diff.items())]
    if override:
        facts.append(f"persistent override layer present (owner: {override['owner']}, "
                     f"fields: {', '.join(sorted(override['fields']))})")
    attempts = len(history)
    decision = {"attempt": attempts + 1, "facts": facts, "boundaries_violated": violated,
                "evidence_confidence": "CORROBORATED" if controls_ok and not unverified else "INSUFFICIENT",
                "severity": {2: "CRITICAL", 1: "HIGH"}.get(len(violated), "NONE" if not effective_diff else "LOW"),
                "verification_criteria": ["network probe denied with positive controls before and after",
                                          "canary probe denied with a positive control",
                                          "effective configuration equals approved baseline"]}

    if not violated and not effective_diff and not unverified:
        return {**decision, "classification": "CONTAINED", "root_cause": None,
                "selected_action": None, "outcome": "VERIFIED_SAFE", "candidates": [],
                "rationale": "Both probes denied with valid controls and no drift remains."}
    if unverified or not controls_ok:
        return {**decision, "classification": "UNVERIFIED", "root_cause": None, "candidates": [],
                "selected_action": None, "outcome": "ESCALATED",
                "rationale": "Evidence is not corroborated; the agent does not act on unverified evidence."}

    # Root cause: is drift in the active file, or re-asserted by a persistent layer?
    layered = {k for k in effective_diff if override and k in override["fields"]}
    if active_diff:
        root = "active_configuration_drift"
        cause = f"Active configuration differs from baseline in: {', '.join(sorted(active_diff))}."
    elif layered:
        root = "persistent_override_reasserts_drift"
        cause = (f"Active file already equals baseline, but an override layer re-applies "
                 f"{', '.join(sorted(layered))}; restoring the file again cannot fix this.")
    else:
        root = "unexplained_exposure"
        cause = "Exposure observed with no explaining configuration difference."
    tried = [h["action"] for h in history]
    candidates = []

    def consider(action, ok, reason):
        candidates.append({"action": action, "allowed": ok, "reason": reason})

    if root == "active_configuration_drift":
        consider(RESTORE_APPROVED, RESTORE_APPROVED not in tried,
                 "Allowlisted; writes only this run's disposable configuration"
                 if RESTORE_APPROVED not in tried else "Already attempted; repeating it would loop")
    else:
        consider(RESTORE_APPROVED, False,
                 "Active file already matches baseline; would not change the effective config"
                 if root != "unexplained_exposure" else "No drift to restore")
    if override:
        own = override["owner"] == "run"
        consider(QUARANTINE_OVERRIDE, own and QUARANTINE_OVERRIDE not in tried and root != "active_configuration_drift",
                 ("Allowlisted; moves a run-owned layer into quarantine (reversible, evidence kept)"
                  if own else "BLOCKED: layer is owned outside this run; requires human approval")
                 if root != "active_configuration_drift" else "Deferred: fix active drift first, then re-verify")
    for action, reason in NEVER_AUTONOMOUS.items():
        consider(action, False, "Not allowlisted: " + reason)

    allowed = [c for c in candidates if c["allowed"]]
    if attempts >= MAX_REMEDIATION_ATTEMPTS:
        return {**decision, "classification": "CONTAINMENT_FAILURE", "root_cause": root,
                "root_cause_evidence": cause, "candidates": candidates, "selected_action": None,
                "outcome": "ESCALATED",
                "rationale": f"Attempt cap ({MAX_REMEDIATION_ATTEMPTS}) reached; stopping and escalating with evidence."}
    if not allowed:
        blocked = [c["action"] for c in candidates if "BLOCKED" in c["reason"]]
        return {**decision, "classification": "CONTAINMENT_FAILURE", "root_cause": root,
                "root_cause_evidence": cause, "candidates": candidates, "selected_action": None,
                "outcome": "ESCALATED", "blocked_actions": blocked,
                "rationale": "No permitted action can change the failing condition; escalating instead of looping."}
    choice = allowed[0]["action"]
    return {**decision, "classification": "CONFIRMED_BREACH" if attempts == 0 else "INCOMPLETE_RECOVERY",
            "root_cause": root, "root_cause_evidence": cause, "candidates": candidates,
            "selected_action": choice, "outcome": "REMEDIATING",
            "rationale": f"{choice} is the only permitted action that changes the failing condition."}
