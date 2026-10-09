"""Offline control-flow tests. No Docker, DNS, HTTPS, or public export is executed."""

import ast
import contextlib
import io
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from test_replay import fixture


class LocalVerifyFlowTests(unittest.TestCase):
    def exercise(self, cloud=False):
        root = Path(__file__).resolve().parents[1]
        source = (root / "scripts/local_verify.sh").read_text().split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
        tree = ast.parse(source)
        # Load definitions, never the script's invocation block.
        tree.body = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.ClassDef))]
        namespace = {}
        exec(compile(tree, "<local-verifier-unit-test>", "exec"), namespace)
        original_alarm, original_term = signal.getsignal(signal.SIGALRM), signal.getsignal(signal.SIGTERM)
        self.addCleanup(signal.signal, signal.SIGALRM, original_alarm)
        self.addCleanup(signal.signal, signal.SIGTERM, original_term)
        with tempfile.TemporaryDirectory() as directory:
            task_root = Path(directory).resolve()
            namespace["ROOT"] = task_root
            calls = []

            def fake_command(argv, **kwargs):
                if argv[0] == "docker":
                    return subprocess.CompletedProcess(argv, 0, json.dumps({"Os": "linux"}), "")
                return subprocess.CompletedProcess(argv, 0, "1.100.0\n", "")

            def fake_demo(argv):
                calls.append("demo")
                target = Path(argv[argv.index("--evidence-dir") + 1])
                path = fixture(target)
                raw = {"results": [{"check_id": rule, "path": "configs/drift.yaml", "start": {"line": 3},
                                     "extra": {"message": "UNIT_TEST_ONLY"}}
                                    for rule in ("escape-room-canary-mount", "escape-room-collector-network")],
                       "errors": [], "paths": {"scanned": ["configs/secure.yaml", "configs/drift.yaml"]}}
                path.with_name(path.stem + ".semgrep.json").write_text(json.dumps(raw))
                return 0

            namespace["command"] = fake_command
            with patch.object(sys, "argv", ["local_verify", "--with-cloud" if cloud else "--local-only"]), \
                    patch.object(sys, "prefix", str(task_root / ".venv")), \
                    patch.dict(os.environ, {"DOCKER_HOST": "unix:///UNIT_TEST_ONLY.sock", "DOCKER_CONTEXT": ""}), \
                    patch("shutil.which", return_value="UNIT_TEST_EXECUTABLE"), \
                    patch.object(namespace["demo"], "main", side_effect=fake_demo), \
                    patch.object(namespace["Settings"], "load", return_value=SimpleNamespace(secure=True, host="unit.invalid", port=8443, password="UNIT_TEST_SECRET")) as settings, \
                    patch("socket.getaddrinfo", side_effect=socket.gaierror("UNIT_TEST_DNS_FAILURE")) as dns, \
                    patch("http.client.HTTPSConnection", side_effect=AssertionError("Network must not be used")), \
                    patch("engine.replay.export_replay", return_value={}) as export, \
                    contextlib.redirect_stdout(io.StringIO()):
                result = namespace["main"]()
                debug_report = next(task_root.glob("evidence/local-verify/*/report.json")).read_text()
                self.assertEqual(result, 0, debug_report)
                self.assertEqual(calls, ["demo", "demo"])
                export.assert_called_once()
                if cloud:
                    dns.assert_called_once()
                else:
                    dns.assert_not_called()
                    settings.assert_not_called()
            report = json.loads(next(task_root.glob("evidence/local-verify/*/report.json")).read_text())
            self.assertEqual(report["status"], "PASS")
            self.assertTrue(report["cloud_optional"])
            self.assertEqual(report["checks"][2]["status"], "INCONCLUSIVE")
            self.assertEqual(report["checks"][5]["status"], "PASS")
            self.assertEqual(report["checks"][6]["status"], "PASS")

    def test_local_only_never_reads_cloud_settings_or_calls_dns(self):
        self.exercise()

    def test_optional_cloud_failure_does_not_block_local_pass(self):
        self.exercise(cloud=True)
