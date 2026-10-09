"""Deterministic event-driven response; the only actuator restores the baseline."""

from collections import deque
from dataclasses import dataclass
from enum import Enum

from .events import FAIL, INCONCLUSIVE, PASS
from .gate import record_gate
from .policy import RESTORE_APPROVED, diff


class State(str, Enum):
    MONITORING = "MONITORING"
    DRIFT_DETECTED = "DRIFT_DETECTED"
    PROBING = "PROBING"
    INCIDENT_CONFIRMED = "INCIDENT_CONFIRMED"
    REMEDIATING = "REMEDIATING"
    VERIFYING = "VERIFYING"
    RECOVERED = "RECOVERED"


ORDER = list(State)


@dataclass
class Response:
    incident: object = None
    recovered: object = None


class Agent:
    def __init__(self, store, probes, log, advisor=None):
        self.store, self.probes, self.log = store, probes, log
        self.advisor = advisor
        self.state = State.MONITORING
        self.queue = deque()
        self.response = Response()
        self.log.emit("AGENT", "state_entered", PASS, "agent",
                      {"state": self.state.value})

    def transition(self, state, trigger, status=PASS):
        if ORDER.index(state) != ORDER.index(self.state) + 1:
            raise RuntimeError("Illegal agent state transition")
        previous = self.state
        self.state = state
        self.log.emit("AGENT", "state_transition", status, "agent",
                      {"from": previous.value, "to": state.value, "trigger": trigger},
                      config_diff=diff(self.store.read()))

    def handle(self, event_type):
        """Consume a configuration notification and drain all follow-up events."""
        self.queue.append(event_type)
        while self.queue:
            event = self.queue.popleft()
            self.log.emit("AGENT", "event_received", PASS, "agent", {"event": event})
            if event == "configuration_changed" and self.state == State.MONITORING:
                changes = diff(self.store.read())
                if not changes:
                    continue
                self.log.emit("DRIFT", "configuration_drift", FAIL, "policy", config_diff=changes)
                self.transition(State.DRIFT_DETECTED, event, FAIL)
                self.queue.append("drift_detected")
            elif event == "drift_detected" and self.state == State.DRIFT_DETECTED:
                self.transition(State.PROBING, event)
                self.response.incident = self.probes.run(self.store.read(), "DRIFT")
                record_gate(self.log, self.store.read(), self.response.incident, phase="DRIFT")
                if self.response.incident.status == FAIL:
                    self.transition(State.INCIDENT_CONFIRMED, "observed_access", FAIL)
                    self.queue.append("incident_confirmed")
                else:
                    self.log.emit("AGENT", "incident_not_confirmed", INCONCLUSIVE, "agent",
                                  {"probes": self.response.incident.statuses(),
                                   "reason": "No observed containment failure; cannot claim an incident"})
            elif event == "incident_confirmed" and self.state == State.INCIDENT_CONFIRMED:
                try:
                    recommendation = self.advisor(self.log) if self.advisor else None
                except Exception:
                    recommendation = None
                    self.log.emit("AGENT", "advisor_unavailable", INCONCLUSIVE, "agent",
                                  {"reason": "Optional advice failed; approved policy retains authority"})
                accepted = recommendation == RESTORE_APPROVED
                self.log.emit("AGENT", "remediation_decision", PASS, "policy",
                              {"action": RESTORE_APPROVED, "model_recommendation_accepted": accepted,
                               "authority": "deterministic_allowlist",
                               "basis": "validated_advice" if accepted else "approved_policy_fallback"})
                self.transition(State.REMEDIATING, event)
                before = diff(self.store.read())
                restored = self.store.remediate(RESTORE_APPROVED)
                self.log.emit("RECOVERY", "approved_configuration_restored", PASS, "policy",
                              {"action": RESTORE_APPROVED, "active": restored.to_dict(),
                               "scope": "disposable run configuration"}, config_diff=before)
                self.queue.append("configuration_restored")
            elif event == "configuration_restored" and self.state == State.REMEDIATING:
                self.transition(State.VERIFYING, event)
                self.response.recovered = self.probes.run(self.store.read(), "RECOVERY")
                record_gate(self.log, self.store.read(), self.response.recovered, phase="RECOVERY")
                if self.response.recovered.status == PASS and not diff(self.store.read()):
                    self.transition(State.RECOVERED, "both_probes_denied")
                else:
                    self.log.emit("RECOVERY", "recovery_not_verified",
                                  self.response.recovered.status, "agent",
                                  self.response.recovered.statuses())
            else:
                raise ValueError("Unexpected event for agent state: " + event)
        return self.response
