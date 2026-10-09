"""Focused local doubles for credential correction and first-publication authority."""

import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import Mock, patch

from engine.clickhouse import ClickHouseError, Client, Settings, read_env, update_credentials
from engine.intelligence import IntegrationError
from engine.integrations import ALLOWED_REPOSITORY, authorize, confirm_publication, publication_authority
from tests.test_clickhouse import values


class FinalBlockerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.settings = Path(self.temp.name) / ".env.clickhouse"
        self.settings.write_text("\n".join(k + "=" + json.dumps(v) for k, v in values().items()))
        self.settings.chmod(0o600)
        self.authority = Path(self.temp.name) / "authorization.json"

    def test_update_preserves_endpoint_and_quotes_literal_password(self):
        password = 'TEST-ONLY-NEW-$value#"quote'
        before = read_env(self.settings)
        update_credentials("test-user", password, self.settings)
        after = read_env(self.settings)
        self.assertEqual(after["CLICKHOUSE_PASSWORD"], password)
        for key in ("CLICKHOUSE_HOST", "CLICKHOUSE_PORT", "CLICKHOUSE_DATABASE", "CLICKHOUSE_SECURE"):
            self.assertEqual(after[key], before[key])
        self.assertEqual(self.settings.stat().st_mode & 0o777, 0o600)

    def test_unchanged_rejected_pair_is_not_retried_or_rewritten(self):
        original = self.settings.read_bytes()
        data = read_env(self.settings)
        with self.assertRaises(ClickHouseError):
            update_credentials(data["CLICKHOUSE_USER"], data["CLICKHOUSE_PASSWORD"], self.settings)
        self.assertEqual(self.settings.read_bytes(), original)

    def test_401_is_single_request_with_exact_documented_headers(self):
        client = Client(Settings.from_values(values()))
        client.opener = Mock()
        client.opener.open.side_effect = urllib.error.HTTPError("https://example.invalid", 401, "private", {}, io.BytesIO(b"private"))
        with self.assertRaisesRegex(ClickHouseError, "status 401"):
            client.select_one()
        client.opener.open.assert_called_once()
        request = client.opener.open.call_args.args[0]
        headers = {k.lower(): v for k, v in request.header_items()}
        self.assertEqual(headers["x-clickhouse-user"], values()["CLICKHOUSE_USER"])
        self.assertEqual(headers["x-clickhouse-key"], values()["CLICKHOUSE_PASSWORD"])
        self.assertNotIn(values()["CLICKHOUSE_PASSWORD"], request.full_url)

    def test_exact_target_and_confirmation_are_both_required(self):
        with patch("engine.integrations.AUTHORIZATION", self.authority):
            with self.assertRaises(IntegrationError): authorize("other-owner/escape-room")
            authorize(ALLOWED_REPOSITORY)
            with self.assertRaises(IntegrationError): publication_authority()
            with patch("engine.integrations.sys.stdin.isatty", return_value=True), patch("builtins.input", return_value="PUBLISH"), patch("builtins.print"):
                self.assertTrue(confirm_publication([]))
            self.assertEqual(publication_authority(), "vincentleg/escape-room")
            with patch("builtins.input") as prompt:
                self.assertTrue(confirm_publication([]))
                prompt.assert_not_called()

    def test_decline_and_noninteractive_execution_never_confirm(self):
        with patch("engine.integrations.AUTHORIZATION", self.authority), patch("builtins.print"):
            authorize(ALLOWED_REPOSITORY)
            with patch("engine.integrations.sys.stdin.isatty", return_value=True), patch("builtins.input", return_value="no"):
                self.assertFalse(confirm_publication([]))
            with patch("engine.integrations.sys.stdin.isatty", return_value=False):
                self.assertFalse(confirm_publication([]))
            with self.assertRaises(IntegrationError): publication_authority()

    def test_finish_command_never_requests_new_drill_or_openai(self):
        from engine.finish_blockers import main
        with patch("engine.finish_blockers.sys.stdin.isatty", return_value=False), patch("engine.finish_blockers.finish", return_value=2) as finish, patch("builtins.print"):
            self.assertEqual(main(), 2)
        self.assertEqual(finish.call_args.args[0], ["--confirm-publication", "--deploy", "--skip-cloud"])
