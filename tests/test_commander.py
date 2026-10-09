import json
import tempfile
import unittest
from pathlib import Path

from engine.decision import MAX_REMEDIATION_ATTEMPTS, NEVER_AUTONOMOUS, assess, fingerprint
from engine.policy import (APPROVED, QUARANTINE_OVERRIDE, RESTORE_APPROVED, AdmissionRejected,
                           Config, ConfigStore, HumanApprovalRequired, diff)

DRIFT = Config(network="collector", mount_canary=True)
BOTH_FAIL = {"network": "FAIL", "secret": "FAIL"}
NET_FAIL = {"network": "FAIL", "secret": "PASS"}
SAFE = {"network": "PASS", "secret": "PASS"}
RESTORED = [{"action": RESTORE_APPROVED}]


class DecisionTests(unittest.TestCase):
    def test_confirmed_breach_selects_restore_and_rejects_unsafe_actions(self):
        d = assess(BOTH_FAIL, True, diff(DRIFT), diff(DRIFT), None, [])
        self.assertEqual((d["severity"], d["selected_action"]), ("CRITICAL", RESTORE_APPROVED))
        self.assertEqual(d["boundaries_violated"], ["canary_read", "network_egress"])
        rejected = {c["action"] for c in d["candidates"] if not c["allowed"]}
        self.assertTrue(set(NEVER_AUTONOMOUS) <= rejected)

    def test_failed_verification_diagnoses_override_and_switches_action(self):
        override = {"owner": "run", "fields": {"network": "collector"}}
        eff = diff(Config(network="collector"))
        d = assess(NET_FAIL, True, {}, eff, override, RESTORED)
        self.assertEqual(d["root_cause"], "persistent_override_reasserts_drift")
        self.assertEqual(d["selected_action"], QUARANTINE_OVERRIDE)
        self.assertFalse(next(c for c in d["candidates"] if c["action"] == RESTORE_APPROVED)["allowed"])

    def test_externally_owned_override_escalates_without_acting(self):
        override = {"owner": "external", "fields": {"network": "collector"}}
        d = assess(NET_FAIL, True, {}, diff(Config(network="collector")), override, RESTORED)
        self.assertEqual((d["outcome"], d["selected_action"]), ("ESCALATED", None))
        self.assertIn(QUARANTINE_OVERRIDE, d["blocked_actions"])

    def test_attempt_cap_and_unverified_evidence_stop_safely(self):
        history = [{"action": RESTORE_APPROVED}] * MAX_REMEDIATION_ATTEMPTS
        self.assertEqual(assess(BOTH_FAIL, True, diff(DRIFT), diff(DRIFT), None, history)["outcome"], "ESCALATED")
        d = assess({"network": "INCONCLUSIVE", "secret": "FAIL"}, True, diff(DRIFT), diff(DRIFT), None, [])
        self.assertEqual((d["outcome"], d["selected_action"]), ("ESCALATED", None))
        self.assertEqual(assess(BOTH_FAIL, False, diff(DRIFT), diff(DRIFT), None, [])["outcome"], "ESCALATED")

    def test_verified_safe_only_when_probes_denied_and_no_drift(self):
        self.assertEqual(assess(SAFE, True, {}, {}, None, RESTORED)["outcome"], "VERIFIED_SAFE")
        self.assertNotEqual(assess(SAFE, True, {}, diff(DRIFT), None, RESTORED)["outcome"], "VERIFIED_SAFE")

    def test_fingerprint_separates_root_causes(self):
        a = fingerprint(["network_egress"], diff(DRIFT), ["active_configuration_drift"])
        b = fingerprint(["network_egress"], diff(DRIFT), ["active_configuration_drift", "persistent_override_reasserts_drift"])
        self.assertNotEqual(a, b)
        self.assertEqual(a, fingerprint(["network_egress"], diff(DRIFT), ["active_configuration_drift"]))


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.store = ConfigStore(self.dir.name)

    def tearDown(self):
        self.dir.cleanup()

    def test_override_survives_restore_until_quarantined(self):
        self.store.inject_drift(DRIFT)
        self.store.inject_override({"network": "collector"}, "run")
        self.assertEqual(self.store.remediate(RESTORE_APPROVED).network, "collector")
        self.assertEqual(self.store.remediate(QUARANTINE_OVERRIDE), APPROVED)
        self.assertTrue((Path(self.dir.name) / "quarantine/override.json").is_file())

    def test_external_override_requires_human_and_unknown_actions_fail(self):
        self.store.inject_override({"network": "collector"}, "external")
        with self.assertRaises(HumanApprovalRequired):
            self.store.remediate(QUARANTINE_OVERRIDE)
        with self.assertRaises(ValueError):
            self.store.remediate("rm -rf /")

    def test_guard_rejects_repeat_drift(self):
        self.store.enable_guard(diff(DRIFT))
        with self.assertRaises(AdmissionRejected):
            self.store.inject_drift(DRIFT)
        with self.assertRaises(AdmissionRejected):
            self.store.inject_override({"mount_canary": True})
        self.assertEqual(self.store.read(), APPROVED)


class PublicExportTests(unittest.TestCase):
    def test_published_scenarios_match_recorded_evidence(self):
        data = json.loads(Path("web/commander.json").read_text())
        outcomes = {r["scenario"]: r["outcome"] for r in data["scenarios"]}
        self.assertEqual(outcomes, {"standard": "VERIFIED_SAFE", "persistent": "VERIFIED_SAFE",
                                    "escalation": "ESCALATED", "recurrence": "RECURRENCE_BLOCKED"})
        text = json.dumps(data)
        for forbidden in ("/Users/", "sk-", "FAKE-ESCAPE-ROOM-CANARY"):
            self.assertNotIn(forbidden, text)
        for run in data["scenarios"]:
            self.assertTrue(run["cleanup_complete"])
            self.assertLessEqual(len(run["attempts"]), run["max_attempts"])
            raw = Path("evidence/commander", run["run_id"] + ".json")
            import hashlib
            self.assertEqual(hashlib.sha256(raw.read_bytes()).hexdigest(), run["source_sha256"])


if __name__ == "__main__":
    unittest.main()
