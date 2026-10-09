"""Replay validation fixtures are unit doubles; none are published as evidence."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from engine.events import EventLog
from engine.replay import export_replay, public_run


def fixture(directory):
    log = EventLog(directory, echo=False)
    log.emit("SETUP", "run_started", "PASS", "demo")

    def probe_pair(phase, status):
        denial = status == "PASS"
        command = {"exit_status": 10 if denial else 0, "timed_out": False, "error": "",
                   "command": ["UNIT_TEST_DOUBLE"], "stdout": "PRIVATE_TEST_ONLY"}
        observed = {"outcome": "denied" if denial else "access", "errno": 101 if denial else None,
                    "collector_token": "UNIT_TEST_TOKEN", "sha256": "UNIT_TEST_DIGEST", "bytes_read": 15}
        log.emit(phase, "network_probe", status, "runtime", {
            "command": command, "probe": observed, "positive_control_before": True,
            "positive_control_after": True, "request_token": "UNIT_TEST_TOKEN",
            "collector_receipt": {"token": "UNIT_TEST_TOKEN"}})
        log.emit(phase, "synthetic_secret_probe", status, "runtime", {
            "command": command, "probe": {**observed, "errno": 2 if denial else None},
            "positive_control": True, "expected_sha256": "UNIT_TEST_DIGEST"})
        log.emit(phase, "security_gate", status, "gate", {"exit_code": 0 if denial else 1})

    def state(name):
        log.emit("AGENT", "state_transition", "PASS", "agent", {"to": name})

    probe_pair("SECURE", "PASS")
    state("DRIFT_DETECTED")
    state("PROBING")
    probe_pair("DRIFT", "FAIL")
    state("INCIDENT_CONFIRMED")
    state("REMEDIATING")
    state("VERIFYING")
    probe_pair("RECOVERY", "PASS")
    state("RECOVERED")
    log.emit("STATIC", "semgrep_finding", "FAIL", "semgrep", {
        "rule_id": "rules.escape-room-canary-mount", "file": "configs/drift.yaml", "line": 3})
    return log.finish("PASS", three_acts_verified=True, cleanup_complete=True,
                      agent_state="RECOVERED", drift_gate_exit=1, recovered_gate_exit=0,
                      secure={"network": "PASS", "secret": "PASS"},
                      drift={"network": "FAIL", "secret": "FAIL"},
                      recovered={"network": "PASS", "secret": "PASS"}, semgrep="INCONCLUSIVE")


class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = fixture(self.temp.name)

    def alter(self, change):
        data = json.loads(self.path.read_text())
        change(data)
        self.path.write_text(json.dumps(data))

    def test_projection_contains_proof_but_no_private_payloads(self):
        result = public_run(self.path)
        serialized = json.dumps(result)
        self.assertEqual(len(result["frames"]), 6)
        self.assertEqual(len(result["probes"]), 6)
        self.assertEqual(result["source_sha256"], hashlib.sha256(self.path.read_bytes()).hexdigest())
        for private in ("PRIVATE_TEST_ONLY", "UNIT_TEST_TOKEN", "UNIT_TEST_DIGEST", "command", "stdout"):
            self.assertNotIn(private, serialized)
        self.assertEqual(result["semgrep_status"], "INCONCLUSIVE")

    def test_rejects_missing_control_timeout_receipt_and_gate(self):
        for damage in ("control", "timeout", "receipt", "gate"):
            with self.subTest(damage=damage):
                original = self.path.read_text()
                def change(data):
                    if damage == "gate":
                        data["events"] = [e for e in data["events"] if e["event_type"] != "security_gate"]
                        return
                    phase = "DRIFT" if damage == "receipt" else "SECURE"
                    evidence = next(e["observed_evidence"] for e in data["events"]
                                    if e["phase"] == phase and e["event_type"] == "network_probe")
                    if damage == "control": evidence["positive_control_before"] = False
                    if damage == "timeout": evidence["command"]["timed_out"] = True
                    if damage == "receipt": evidence["collector_receipt"] = None
                self.alter(change)
                with self.assertRaises(ValueError): public_run(self.path)
                self.path.write_text(original)

    def test_rejects_out_of_order_states(self):
        def change(data):
            index = next(i for i, e in enumerate(data["events"]) if e["event_type"] == "state_transition")
            data["events"][index]["observed_evidence"]["to"] = "RECOVERED"
        self.alter(change)
        with self.assertRaises(ValueError): public_run(self.path)

    def test_export_does_not_modify_original_and_deduplicates_run_ids(self):
        original = self.path.read_bytes()
        target = Path(self.temp.name) / "public.json"
        result = export_replay([self.path, self.path], destination=target)
        self.assertEqual(result["verified_run_count"], 1)
        self.assertEqual(result["cloud_ingestion"], "UNVERIFIED")
        self.assertEqual(self.path.read_bytes(), original)

    def test_failed_export_does_not_replace_good_public_record(self):
        target = Path(self.temp.name) / "public.json"
        target.write_text("existing-public-record")
        self.alter(lambda d: d["events"].pop())
        with self.assertRaises(RuntimeError): export_replay([self.path], destination=target)
        self.assertEqual(target.read_text(), "existing-public-record")
