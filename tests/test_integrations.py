"""Explicit API/CLI doubles; never export these fixtures as execution evidence."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from engine.agent import Agent, State
from engine.events import EventLog
from engine.intelligence import IntegrationError, analyze, incident_evidence, validate_advice
from engine.integrations import ingest, issue_content, projection, publish, process_artifact
from engine.policy import APPROVED, Config, ConfigStore, RESTORE_APPROVED
from engine.replay import public_run
from tests.test_engine import bundle
from tests.test_replay import fixture


def advice():
    return {"summary": "Observed collector access and verified canary reads violate both approved isolation boundaries.",
            "violations": ["network_egress", "canary_read"], "recommended_action": RESTORE_APPROVED}


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = fixture(self.temp.name)
        self.document = json.loads(self.path.read_text())
        self.run = public_run(self.path)

    def test_advisor_receives_only_corroborated_sanitized_facts(self):
        facts = incident_evidence(self.document["events"])
        serialized = json.dumps(facts)
        for private in ("PRIVATE_TEST", "UNIT_TEST", "stdout", "command", "sha256"):
            self.assertNotIn(private, serialized)
        self.assertEqual(facts["allowed_actions"], [RESTORE_APPROVED])
        event = next(e for e in self.document["events"] if e["phase"] == "DRIFT" and e["event_type"] == "network_probe")
        event["observed_evidence"]["collector_receipt"] = None
        with self.assertRaises(IntegrationError): incident_evidence(self.document["events"])

    def test_model_cannot_add_commands_or_change_allowed_action(self):
        for invalid in ({**advice(), "command": "rm -rf /"},
                        {**advice(), "recommended_action": "run_shell"},
                        {**advice(), "violations": ["network_egress"]},
                        {**advice(), "summary": "https://example.invalid/private"}):
            with self.subTest(value=invalid), self.assertRaises(IntegrationError): validate_advice(invalid)

    def test_real_protocol_shape_and_private_response_storage_with_test_double(self):
        payload = {"id": "resp_UNIT_TEST", "status": "completed", "output": [
            {"type": "message", "content": [{"type": "output_text", "text": json.dumps(advice())}]}]}
        response = Mock(status=200)
        response.read.return_value = json.dumps(payload).encode()
        opener = Mock()
        opener.open.return_value.__enter__ = Mock(return_value=response)
        opener.open.return_value.__exit__ = Mock(return_value=False)
        directory = Path(self.temp.name) / "private"
        result = analyze(self.document["events"], self.run["run_id"], key="UNIT_TEST_API_KEY", opener=opener, private_dir=directory)
        request = opener.open.call_args.args[0]
        body = json.loads(request.data)
        self.assertEqual(request.full_url, "https://api.openai.com/v1/responses")
        self.assertFalse(body["store"])
        self.assertNotIn("tools", body)
        self.assertNotIn("UNIT_TEST_API_KEY", request.data.decode())
        self.assertEqual(result["recommended_action"], RESTORE_APPROVED)
        saved = next(directory.glob("*.json"))
        self.assertEqual(saved.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(saved.read_text())["response"], payload)

    def test_untrusted_or_broken_advisor_does_not_control_restore(self):
        for callback in (lambda log: "run_shell", Mock(side_effect=RuntimeError("private")), lambda log: RESTORE_APPROVED):
            with tempfile.TemporaryDirectory() as directory:
                log = EventLog(directory, echo=False)
                try:
                    store = ConfigStore(directory)
                    store.inject_drift(Config("collector", True))
                    probes = Mock()
                    probes.run.side_effect = [bundle("FAIL", "FAIL"), bundle()]
                    agent = Agent(store, probes, log, advisor=callback)
                    agent.handle("configuration_changed")
                    self.assertEqual(agent.state, State.RECOVERED)
                    self.assertEqual(store.read(), APPROVED)
                finally:
                    log._file.close()

    def test_no_publication_without_exact_authorization(self):
        with patch("engine.integrations.AUTHORIZATION", Path(self.temp.name) / "absent"), patch("engine.integrations.gh") as client:
            with self.assertRaises(IntegrationError): publish(self.run, {}, Mock())
            client.assert_not_called()

    def test_unverified_recovery_never_reaches_external_actions(self):
        self.document["summary"]["cleanup_complete"] = False
        self.path.write_text(json.dumps(self.document))
        with patch("engine.integrations.gh") as client, patch("engine.integrations.ingest") as cloud:
            with self.assertRaises((RuntimeError, ValueError)): process_artifact(self.path)
            client.assert_not_called()
            cloud.assert_not_called()

    def test_github_readback_and_idempotency(self):
        title, body = issue_content(self.run)
        repository = "test-owner/test-repo"
        server = {"number": 4, "title": title, "body": body,
                  "html_url": "https://github.com/test-owner/test-repo/issues/4"}
        with patch("engine.integrations.publication_authority", return_value=repository), patch("engine.integrations.gh", side_effect=[[server], server]) as client:
            attempted = Mock()
            receipt = publish(self.run, {}, attempted)
            self.assertTrue(receipt["readback_verified"])
            attempted.assert_not_called()
            self.assertFalse(any("POST" in call.args[0] for call in client.call_args_list))
        with patch("engine.integrations.publication_authority", return_value=repository), patch("engine.integrations.gh", return_value=[]):
            with self.assertRaises(IntegrationError): publish(self.run, {"github_attempted_at": "uncertain"}, Mock())
        for private in ("UNIT_TEST", "PRIVATE_TEST", "stdout", "collector_token"):
            self.assertNotIn(private, body)

    def test_github_creates_only_fixed_report_and_rejects_readback_mismatch(self):
        repository = "test-owner/test-repo"
        with patch("engine.integrations.publication_authority", return_value=repository), patch("engine.integrations.gh", side_effect=[[], {"number": 4}, {"html_url": "https://example.invalid"}]) as client:
            attempted = Mock()
            with self.assertRaises(IntegrationError): publish(self.run, {}, attempted)
            attempted.assert_called_once()
            self.assertEqual(client.call_args_list[1].args[1], dict(zip(("title", "body"), issue_content(self.run))))

    def test_cloud_receipt_requires_count_and_run_readback(self):
        count = len(self.document["events"])
        client = Mock()
        client.query.return_value = json.dumps({"run_id": self.run["run_id"], "events": count})
        with patch("engine.integrations.Client", return_value=client), patch("engine.integrations.Settings.load"), patch("engine.integrations.upload", return_value={"events_verified": count}):
            self.assertEqual(ingest(self.path, self.run, Mock())["events_verified"], count)
            client.query.return_value = json.dumps({"run_id": "different-run", "events": count})
            with self.assertRaises(IntegrationError): ingest(self.path, self.run, Mock())

    def test_public_receipts_ignore_private_fields_and_wrong_source_hash(self):
        receipt = {"run_id": self.run["run_id"], "source_sha256": self.run["source_sha256"],
                   "clickhouse": {"status": "PASS", "timestamp": self.run["recorded_at"], "select_one": 1,
                                  "readback_verified": True, "events_uploaded": 10, "events_verified": 10,
                                  "password": "UNIT_TEST_PRIVATE"}}
        clean = projection(self.run, receipt)
        self.assertEqual(clean["clickhouse"]["status"], "PASS")
        self.assertNotIn("UNIT_TEST_PRIVATE", json.dumps(clean))
        receipt["source_sha256"] = "0" * 64
        self.assertEqual(projection(self.run, receipt)["clickhouse"]["status"], "INCONCLUSIVE")
