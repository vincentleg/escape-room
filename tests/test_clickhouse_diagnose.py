"""Local error-response doubles only; no ClickHouse requests."""

import io
import json
import unittest
import urllib.error
from dataclasses import replace
from unittest.mock import Mock, patch

from engine.clickhouse import ClickHouseError, Client, Settings
from engine.clickhouse_diagnose import main, sanitize_error
from tests.test_clickhouse import values


class DiagnosticTests(unittest.TestCase):
    def test_credentials_and_escaped_values_are_redacted(self):
        settings = Settings.from_values(values())
        body = ("Code: 516. Authentication failed: " + settings.user + " " + settings.password
                + " " + json.dumps(settings.password) + " " + settings.host).encode()
        result = sanitize_error(body, 403, settings)
        self.assertEqual(result["cause_hint"], "sql_credentials_rejected")
        self.assertEqual(result["clickhouse_exception_code"], 516)
        for secret in (settings.user, settings.password, settings.host):
            self.assertNotIn(secret, json.dumps(result))
        encoded = replace(settings, password="TEST-%41&amp;-ONLY")
        clean = sanitize_error(encoded.password.encode(), 403, encoded)
        self.assertNotIn("TEST-A&-ONLY", json.dumps(clean))

    def test_http_diagnostic_does_not_retry_or_change_default_error_string(self):
        client = Client(Settings.from_values(values()), diagnostics=True)
        client.opener = Mock()
        client.opener.open.side_effect = urllib.error.HTTPError("https://example.invalid", 403, "", {}, io.BytesIO(b"IP address is not allowed"))
        with self.assertRaisesRegex(ClickHouseError, r"^ClickHouse HTTP request failed \(status 403\)$"):
            client.select_one()
        client.opener.open.assert_called_once()
        self.assertEqual(client.last_http_diagnostic["cause_hint"], "ip_access_restriction_indicated")

    def test_generic_403_does_not_claim_ip_filter(self):
        result = sanitize_error(b"Forbidden", 403, Settings.from_values(values()))
        self.assertEqual(result["cause_hint"], "unknown_do_not_infer_from_http_status_alone")

    def test_default_override_only_changes_this_request(self):
        original = Settings.from_values(values())
        with patch("engine.clickhouse_diagnose.Settings.load", return_value=original), patch("engine.clickhouse_diagnose.Client") as client, patch("builtins.print"):
            client.return_value.select_one.return_value = {"result": 1}
            self.assertEqual(main(["--default-user"]), 0)
            client.return_value.select_one.assert_called_once()
            self.assertEqual(client.call_args.args[0].user, "default")
            self.assertEqual(original.user, "test-user")
