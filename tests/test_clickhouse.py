"""Credential and telemetry tests use fake secrets/I/O, never runtime evidence."""

import io
import json
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import Mock, patch

from engine.clickhouse import ClickHouseError, Client, NoRedirects, Settings, read_env, repair_settings
from engine.events import EventLog
from engine.telemetry import load_artifact, scrub, upload

FAKE = 'UNIT-TEST-ONLY-Secret$with#"quotes'


def values():
    return {"CLICKHOUSE_HOST": "example.invalid", "CLICKHOUSE_PORT": "8443",
            "CLICKHOUSE_USER": "test-user", "CLICKHOUSE_PASSWORD": FAKE,
            "CLICKHOUSE_SECURE": "true", "CLICKHOUSE_DATABASE": "default"}


class LocalSettingsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / ".env.clickhouse"

    def write(self, path, data):
        path.write_text("\n".join(k + "=" + json.dumps(v) for k, v in data.items()) + "\n")
        path.chmod(0o600)

    def test_empty_file_repaired_from_local_backup_without_exposing_password(self):
        self.path.touch(mode=0o600)
        backup = self.path.with_name(self.path.name + ".save")
        data = values()
        del data["CLICKHOUSE_DATABASE"]
        self.write(backup, data)
        original = backup.read_bytes()
        report = repair_settings(self.path)
        settings = Settings.load(self.path)
        self.assertEqual(settings.password, FAKE)
        self.assertEqual(settings.database, "default")
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(backup.read_bytes(), original)
        self.assertNotIn(FAKE, str(report))
        self.assertNotIn(FAKE, repr(settings))

    def test_current_values_take_precedence(self):
        self.write(self.path, values())
        self.write(self.path.with_name(self.path.name + ".save"), {**values(), "CLICKHOUSE_PASSWORD": "old-fake"})
        repair_settings(self.path)
        self.assertEqual(Settings.load(self.path).password, FAKE)

    def test_missing_secret_never_overwrites_existing_settings(self):
        data = values()
        del data["CLICKHOUSE_PASSWORD"]
        self.write(self.path, data)
        before = self.path.read_bytes()
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(ClickHouseError):
            repair_settings(self.path)
        self.assertEqual(before, self.path.read_bytes())

    def test_no_shell_expansion_and_hash_is_literal_inside_password(self):
        self.path.write_text("CLICKHOUSE_PASSWORD=literal$HOME#value\n")
        self.path.chmod(0o600)
        self.assertEqual(read_env(self.path)["CLICKHOUSE_PASSWORD"], "literal$HOME#value")

    def test_rejects_symlinks_permissions_and_malformed_lines(self):
        target = Path(self.temp.name) / "target"
        target.write_text("test")
        self.path.symlink_to(target)
        with self.assertRaises(ClickHouseError):
            read_env(self.path)
        self.path.unlink()
        self.write(self.path, values())
        self.path.chmod(0o644)
        with self.assertRaises(ClickHouseError):
            read_env(self.path)
        self.path.chmod(0o600)
        self.path.write_text("CLICKHOUSE_PASSWORD='unclosed\n")
        with self.assertRaises(ClickHouseError) as exc:
            read_env(self.path)
        self.assertNotIn("unclosed", str(exc.exception))

    def test_remote_cleartext_url_credentials_and_sql_identifiers_rejected(self):
        for changes in ({"CLICKHOUSE_SECURE": "false"},
                        {"CLICKHOUSE_HOST": "https://user:secret@example.invalid"},
                        {"CLICKHOUSE_DATABASE": "default;DROP TABLE x"},
                        {"CLICKHOUSE_PASSWORD": "changeme"},
                        {"CLICKHOUSE_PASSWORD": "fake\nheader"}):
            with self.subTest(keys=list(changes)), self.assertRaises(ClickHouseError):
                Settings.from_values({**values(), **changes})


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.client = Client(Settings.from_values(values()))
        self.client.opener = Mock()

    def respond(self, payload, status=200):
        response = Mock(status=status)
        response.read.return_value = payload
        self.client.opener.open.return_value.__enter__ = Mock(return_value=response)
        self.client.opener.open.return_value.__exit__ = Mock(return_value=False)

    def test_select_one_sends_password_only_in_header(self):
        self.respond(b"1\n")
        self.assertTrue(self.client.select_one()["verified"])
        request = self.client.opener.open.call_args.args[0]
        self.assertEqual(request.data, b"SELECT 1")
        self.assertNotIn(FAKE, request.full_url)
        self.assertNotIn(FAKE, repr(request))
        self.assertIn(FAKE, request.headers.values())

    def test_query_body_or_nonone_response_cannot_pass(self):
        for payload in (b"0\n", b"Code: 999. DB::Exception: fake error", b"", b"unexpected"):
            with self.subTest(payload=payload):
                self.respond(payload)
                with self.assertRaises(ClickHouseError):
                    self.client.select_one()

    def test_network_and_http_errors_do_not_expose_server_body_or_secret(self):
        for error in (urllib.error.URLError(FAKE),
                      urllib.error.HTTPError("https://example.invalid", 403, FAKE, {}, io.BytesIO(FAKE.encode()))):
            self.client.opener.open.side_effect = error
            with self.assertRaises(ClickHouseError) as exc:
                self.client.select_one()
            self.assertNotIn(FAKE, str(exc.exception))

    def test_redirect_cannot_forward_credentials(self):
        with self.assertRaises(ClickHouseError):
            NoRedirects().redirect_request(None, None, 302, "", {}, "https://elsewhere.invalid")


class TelemetryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "unit-fixture.json"
        self.log = EventLog(Path(self.temp.name) / "logs", echo=False)
        self.addCleanup(self.log._file.close)
        run_id = "a" * 32
        event = {"run_id": run_id, "timestamp": "2026-10-09T12:00:00.000+00:00",
                 "phase": "SETUP", "event_type": "run_started", "status": "PASS",
                 "source": "demo", "observed_evidence": {}, "config_diff": {}}
        summary = {"three_acts_verified": False, "exit_code": 2}
        self.doc = {"schema_version": 1, "run_id": run_id, "status": "INCONCLUSIVE",
                    "summary": summary, "events": [event, {**event, "phase": "SUMMARY",
                        "event_type": "run_completed", "status": "INCONCLUSIVE",
                        "source": "engine", "observed_evidence": summary}]}
        self.save()

    def save(self):
        self.path.write_text(json.dumps(self.doc))

    def test_status_scope_order_and_event_ids_are_preserved(self):
        rows = load_artifact(self.path)
        self.assertEqual([r["status"] for r in rows], ["PASS", "INCONCLUSIVE"])
        self.assertEqual([r["event_index"] for r in rows], [0, 1])
        self.assertTrue(all(r["run_status"] == "INCONCLUSIVE" for r in rows))
        self.assertEqual(rows, load_artifact(self.path))
        self.assertEqual(rows[0]["verification_scope"], "three_act_demo")

    def test_unit_report_and_unfinished_artifacts_rejected(self):
        for change in ("unit", "incomplete", "wrong_run"):
            with self.subTest(change=change):
                original = json.loads(json.dumps(self.doc))
                if change == "unit":
                    self.doc["summary"]["scope"] = "unit_tests_only"
                elif change == "incomplete":
                    self.doc["events"].pop()
                else:
                    self.doc["events"][0]["run_id"] = "b" * 32
                self.save()
                with self.assertRaises(ClickHouseError):
                    load_artifact(self.path)
                self.doc = original

    def test_credentials_scrubbed_before_serialization(self):
        self.doc["events"][0]["observed_evidence"] = {"password": "another-fake", "output": FAKE}
        self.save()
        serialized = json.dumps(load_artifact(self.path, secret=FAKE))
        self.assertNotIn("another-fake", serialized)
        self.assertNotIn(json.dumps(FAKE)[1:-1], serialized)
        self.assertEqual(scrub({"authorization": "fake"}, FAKE), {"authorization": "<redacted>"})

    def client(self, readback):
        client = Mock(settings=Settings.from_values(values()))
        client.query.side_effect = ["", "", readback]
        return client

    def test_upload_requires_exact_server_readback(self):
        rows = load_artifact(self.path)
        response = "\n".join(json.dumps({"event_id": row["event_id"]}) for row in rows)
        client = self.client(response)
        result = upload(client, self.path, self.log)
        self.assertEqual(result["events_verified"], 2)
        client.select_one.assert_called_once()
        self.assertEqual(self.log.events[-1]["event_type"], "telemetry_ingestion_verified")
        self.assertIn("FINAL", client.query.call_args.args[0])

    def test_missing_readback_rows_never_claim_ingestion(self):
        with self.assertRaises(ClickHouseError):
            upload(self.client(""), self.path, self.log)
        self.assertFalse(any(e["event_type"] == "telemetry_ingestion_verified" for e in self.log.events))


if __name__ == "__main__":
    unittest.main()
