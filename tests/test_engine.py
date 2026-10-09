"""Unit tests use explicit doubles; none of their output is runtime evidence."""

import errno
import hashlib
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from engine.agent import Agent, State
from engine.events import FAIL, INCONCLUSIVE, PASS, EventLog
from engine.gate import EXIT_CODES, evaluate
from engine.policy import APPROVED, Config, ConfigStore, RESTORE_APPROVED, diff, load_config
from engine.probes import NETWORK_SCRIPT, SECRET_SCRIPT, ProbeResult, Probes, ProbeSet, decode
from engine.process import CommandResult, execute, run_cli
from engine.runner import InfrastructureError, LABEL, Runner
from engine.static import Scan, scan, verify_samples


def command(code=0, output="", *, timeout=False, error="", stderr=""):
    return CommandResult(["UNIT_TEST_DOUBLE"], "start", "end", 1, code,
                         json.dumps(output) if isinstance(output, dict) else output,
                         stderr, timeout, error)


def bundle(network=PASS, secret=PASS):
    return ProbeSet(ProbeResult("network", network, {}), ProbeResult("secret", secret, {}))


class LoggedTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.log = EventLog(Path(self.temp.name) / "events", echo=False)
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.log._file.close)


class PolicyTests(LoggedTest):
    def test_strict_configuration(self):
        for data in ({"network": "host", "mount_canary": False},
                     {"network": "none", "mount_canary": "false"},
                     {"network": "none", "mount_canary": 0},
                     {"network": "none", "mount_canary": False, "privileged": True},
                     {}, [], None):
            path = Path(self.temp.name) / "test.yaml"
            path.write_text(json.dumps(data))
            with self.subTest(data=data), self.assertRaises(ValueError):
                load_config(path)

    def test_duplicate_keys_rejected(self):
        path = Path(self.temp.name) / "duplicate.yaml"
        path.write_text('{"network":"none","network":"collector","mount_canary":false}')
        with self.assertRaises(ValueError):
            load_config(path)

    def test_baseline_cannot_be_changed_by_input_file(self):
        self.assertEqual(APPROVED, Config())
        self.assertEqual(set(diff(Config("collector", True))), {"network", "mount_canary"})

    def test_only_allowlisted_restore(self):
        store = ConfigStore(self.temp.name)
        store.inject_drift(Config("collector", True))
        with self.assertRaises(ValueError):
            store.remediate("run_shell_command")
        self.assertEqual(store.read(), Config("collector", True))
        self.assertEqual(store.remediate(RESTORE_APPROVED), APPROVED)


class AgentTests(LoggedTest):
    def agent(self, results):
        store = ConfigStore(self.temp.name)
        probes = Mock()
        probes.run.side_effect = results
        return Agent(store, probes, self.log), store, probes

    def test_full_event_driven_recovery(self):
        agent, store, probes = self.agent([bundle(FAIL, FAIL), bundle()])
        store.inject_drift(Config("collector", True))
        response = agent.handle("configuration_changed")
        self.assertEqual(agent.state, State.RECOVERED)
        self.assertEqual(response.recovered.status, PASS)
        self.assertEqual(store.read(), APPROVED)
        states = [e["observed_evidence"]["to"] for e in self.log.events
                  if e["event_type"] == "state_transition"]
        self.assertEqual(states, [s.value for s in list(State)[1:]])
        self.assertEqual(probes.run.call_args_list[0].args, (Config("collector", True), "DRIFT"))
        self.assertEqual(probes.run.call_args_list[1].args, (APPROVED, "RECOVERY"))

    def test_one_confirmed_failure_also_triggers_restore(self):
        agent, store, _ = self.agent([bundle(FAIL, INCONCLUSIVE), bundle()])
        store.inject_drift(Config("collector", True))
        agent.handle("configuration_changed")
        self.assertEqual(agent.state, State.RECOVERED)

    def test_inconclusive_incident_does_not_claim_recovery(self):
        agent, store, probes = self.agent([bundle(INCONCLUSIVE, PASS)])
        store.inject_drift(Config("collector", True))
        response = agent.handle("configuration_changed")
        self.assertEqual(agent.state, State.PROBING)
        self.assertIsNone(response.recovered)
        self.assertEqual(probes.run.call_count, 1)

    def test_failed_retest_never_recovers(self):
        for outcome in (FAIL, INCONCLUSIVE):
            with self.subTest(outcome=outcome):
                agent, store, _ = self.agent([bundle(FAIL, FAIL), bundle(outcome, PASS)])
                store.inject_drift(Config("collector", True))
                agent.handle("configuration_changed")
                self.assertEqual(agent.state, State.VERIFYING)

    def test_no_drift_does_not_probe(self):
        agent, _, probes = self.agent([])
        agent.handle("configuration_changed")
        probes.run.assert_not_called()
        self.assertEqual(agent.state, State.MONITORING)

    def test_invalid_events_and_skipped_states_rejected(self):
        agent, _, _ = self.agent([])
        with self.assertRaises(ValueError):
            agent.handle("incident_confirmed")
        with self.assertRaises(RuntimeError):
            agent.transition(State.RECOVERED, "untrusted")


class ProbeTests(LoggedTest):
    def setUp(self):
        super().setUp()
        self.runner = Mock(collector_ip="172.19.0.2", canary_digest="expected")
        self.probes = Probes(self.runner, self.log)

    def test_timeout_docker_failure_and_invalid_output_are_inconclusive(self):
        for result in (command(None, timeout=True), command(125), command(0, "not json"),
                       command(0, error="Cannot execute docker"), command(20, {"outcome": "error"})):
            with self.subTest(result=result):
                self.runner.run_probe.return_value = result
                self.assertEqual(self.probes.network_attempt(APPROVED, "TEST").status, INCONCLUSIVE)

    def test_network_requires_matching_client_and_collector_evidence(self):
        self.runner.run_probe.return_value = command(0, {"outcome": "access", "collector_token": "token"})
        self.runner.collector_receipt.return_value = {"event": "collector_received", "token": "token"}
        with patch("engine.probes.uuid.uuid4", return_value=Mock(hex="token")):
            self.assertEqual(self.probes.network_attempt(APPROVED, "TEST").status, FAIL)
            self.runner.collector_receipt.return_value = None
            self.assertEqual(self.probes.network_attempt(APPROVED, "TEST").status, INCONCLUSIVE)

    def test_network_requires_both_positive_controls(self):
        denied = ProbeResult("network", PASS, {})
        accessed = ProbeResult("network", FAIL, {})
        broken = ProbeResult("network", INCONCLUSIVE, {})
        for attempts, expected in (([accessed, denied, accessed], PASS),
                                   ([broken, denied, accessed], INCONCLUSIVE),
                                   ([accessed, denied, broken], INCONCLUSIVE),
                                   ([broken, accessed, broken], FAIL)):
            with self.subTest(expected=expected), patch.object(self.probes, "network_attempt", side_effect=attempts):
                self.assertEqual(self.probes.network(APPROVED, "TEST").status, expected)

    def test_connection_refused_is_not_isolation(self):
        self.runner.run_probe.return_value = command(20, {"outcome": "error", "errno": 111})
        self.assertEqual(self.probes.network_attempt(APPROVED, "TEST").status, INCONCLUSIVE)

    def test_canary_requires_positive_control_and_exact_digest(self):
        good = command(0, {"outcome": "access", "sha256": "expected"})
        absent = command(10, {"outcome": "denied", "errno": 2})
        bad = command(0, {"outcome": "access", "sha256": "wrong"})
        for attempts, expected in (([good, absent], PASS), ([good, good], FAIL),
                                   ([bad, absent], INCONCLUSIVE), ([good, bad], INCONCLUSIVE),
                                   ([good, command(None, timeout=True)], INCONCLUSIVE)):
            with self.subTest(expected=expected):
                self.runner.run_probe.side_effect = attempts
                self.assertEqual(self.probes.secret(APPROVED, "TEST").status, expected)

    def test_decode_rejects_nonobject_json(self):
        self.assertEqual(decode(command(0, "[]")), {})


class ScriptTests(unittest.TestCase):
    """Execute the shipped scripts against explicit in-process I/O doubles."""

    def run_script(self, script, argv):
        output = io.StringIO()
        with patch.object(sys, "argv", argv), redirect_stdout(output), self.assertRaises(SystemExit) as exited:
            exec(compile(script, "<probe-unit-test>", "exec"), {})
        return exited.exception.code, json.loads(output.getvalue())

    def test_network_errno_classification(self):
        for number, expected in ((errno.ENETUNREACH, 10), (errno.EHOSTUNREACH, 10),
                                 (errno.EPERM, 10), (errno.EACCES, 10),
                                 (errno.ECONNREFUSED, 20), (errno.ETIMEDOUT, 20)):
            with self.subTest(number=number), patch("http.client.HTTPConnection", side_effect=OSError(number, "unit test")):
                code, data = self.run_script(NETWORK_SCRIPT, ["probe", "127.0.0.1", "token"])
                self.assertEqual(code, expected)
                self.assertEqual(data["outcome"], "denied" if expected == 10 else "error")

    def test_network_timeout_is_error(self):
        with patch("http.client.HTTPConnection", side_effect=TimeoutError("unit test")):
            self.assertEqual(self.run_script(NETWORK_SCRIPT, ["probe", "127.0.0.1", "token"])[0], 20)

    def test_network_response_token_is_verified(self):
        for token, expected in (("token", 0), ("other", 20)):
            response = Mock(status=200)
            response.read.return_value = json.dumps({"collector_token": token}).encode()
            with patch("http.client.HTTPConnection") as connect:
                connect.return_value.getresponse.return_value = response
                self.assertEqual(self.run_script(NETWORK_SCRIPT, ["probe", "127.0.0.1", "token"])[0], expected)

    def test_canary_reads_actual_stream_and_checks_hash(self):
        fake = b"FAKE-CANARY-UNIT-TEST"
        for digest, expected in ((hashlib.sha256(fake).hexdigest(), 0), ("wrong", 20)):
            with patch("builtins.open", return_value=io.BytesIO(fake)):
                code, _ = self.run_script(SECRET_SCRIPT, ["probe", digest])
                self.assertEqual(code, expected)

    def test_canary_absence_permission_and_other_errors(self):
        for error, expected in ((FileNotFoundError(2, "missing"), 10),
                                (PermissionError(13, "denied"), 10),
                                (OSError(5, "io error"), 20)):
            with patch("builtins.open", side_effect=error):
                code, _ = self.run_script(SECRET_SCRIPT, ["probe", "digest"])
                self.assertEqual(code, expected)


class GateTests(unittest.TestCase):
    def test_policy_violation_blocks_without_docker(self):
        self.assertEqual(EXIT_CODES[evaluate(Config("collector", True))], 1)

    def test_runtime_is_required_by_default(self):
        self.assertEqual(EXIT_CODES[evaluate(APPROVED)], 2)
        self.assertEqual(EXIT_CODES[evaluate(APPROVED, bundle())], 0)
        self.assertEqual(EXIT_CODES[evaluate(APPROVED, bundle(INCONCLUSIVE, PASS))], 2)
        self.assertEqual(EXIT_CODES[evaluate(APPROVED, bundle(FAIL, PASS))], 1)

    def test_policy_only_is_explicit(self):
        self.assertEqual(evaluate(APPROVED, policy_only=True), PASS)


class RunnerTests(LoggedTest):
    def setUp(self):
        super().setUp()
        self.runner = Runner(self.log)
        self.addCleanup(self.runner.temporary.cleanup)

    def test_container_restrictions_and_exact_mount(self):
        self.runner.image_id = "sha256:" + "a" * 64
        self.runner.collector_ip = "172.19.0.2"
        with patch.object(self.runner, "command", return_value=command()) as call:
            self.runner.run_probe(APPROVED, "print('test')", [], "TEST")
            args = call.call_args.args[0]
            self.assertEqual(args[args.index("--network") + 1], "none")
            self.assertNotIn("--mount", args)
            for option in ("--read-only", "--cap-drop", "--security-opt", "--pids-limit", "--memory", "--cpus", "--user"):
                self.assertIn(option, args)
            self.runner.run_probe(Config("collector", True), "print('test')", [], "TEST")
            args = call.call_args.args[0]
            self.assertEqual(args[args.index("--network") + 1], self.runner.network)
            self.assertEqual(args[args.index("--mount") + 1],
                             "type=bind,src=" + str(self.runner.canary_dir) + ",dst=/canary,readonly")
            self.assertNotIn("--privileged", args)
            self.assertNotIn("--publish", args)
            self.assertEqual(self.runner.resources, [])

    def test_cleanup_checks_exact_ownership(self):
        wrong = command(0, json.dumps([{"Config": {"Labels": {LABEL: "another-run"}}}]))
        with patch.object(self.runner, "command", return_value=wrong) as call:
            self.assertFalse(self.runner.remove_owned("container", "test"))
            self.assertEqual(call.call_count, 1)
        owned = command(0, json.dumps([{"Config": {"Labels": {LABEL: self.log.run_id}}}]))
        with patch.object(self.runner, "command", side_effect=[owned, command()]) as call:
            self.assertTrue(self.runner.remove_owned("container", "test"))
            self.assertEqual(call.call_args.args[0], ["container", "rm", "--force", "test"])

    def test_missing_resource_is_safe_but_daemon_failure_is_not(self):
        for result, expected in ((command(1, stderr="Error: No such container: name"), True),
                                 (command(1, stderr="Cannot connect to daemon"), False),
                                 (command(None, timeout=True), False)):
            with patch.object(self.runner, "command", return_value=result):
                self.assertEqual(self.runner.remove_owned("container", "test"), expected)

    def test_timed_out_container_is_cleaned_immediately(self):
        self.runner.image_id = "sha256:" + "a" * 64
        self.runner.collector_ip = "172.19.0.2"
        with patch.object(self.runner, "command", return_value=command(None, timeout=True)), \
                patch.object(self.runner, "remove_owned", return_value=True) as cleanup:
            self.runner.run_probe(APPROVED, "script", [], "TEST")
            cleanup.assert_called_once()
            self.assertEqual(self.runner.resources, [])

    def test_remote_docker_endpoint_is_rejected(self):
        with patch.dict("os.environ", {"DOCKER_HOST": "tcp://example.invalid:2375", "DOCKER_CONTEXT": ""}), \
                patch.object(self.runner, "command") as call:
            with self.assertRaises(InfrastructureError):
                self.runner.setup()
            call.assert_not_called()

    def test_close_on_setup_failure(self):
        with self.assertRaises(InfrastructureError):
            with self.runner:
                raise InfrastructureError("test failure")
        self.assertFalse(self.runner.directory.exists())
        self.assertEqual(self.log.events[-1]["event_type"], "cleanup_completed")


class EvidenceTests(LoggedTest):
    def test_event_schema_unique_ids_and_redaction(self):
        event = self.log.emit("TEST", "observed", INCONCLUSIVE, "unit",
                              {"path": str(Path.home() / "private")})
        self.assertEqual(set(event), {"run_id", "timestamp", "phase", "event_type", "status",
                                      "source", "observed_evidence", "config_diff"})
        self.assertNotIn(str(Path.home()), json.dumps(event))
        self.assertTrue(event["timestamp"].endswith("+00:00"))
        artifact = self.log.finish(INCONCLUSIVE, unit_test=True)
        self.assertEqual(json.loads(artifact.read_text())["status"], INCONCLUSIVE)
        second = EventLog(self.log.directory, echo=False)
        self.addCleanup(second._file.close)
        self.assertNotEqual(second.run_id, self.log.run_id)

    def test_invalid_status_rejected(self):
        with self.assertRaises(ValueError):
            self.log.emit("TEST", "event", "SECURE", "unit")


class ProcessTests(unittest.TestCase):
    def test_sigterm_unwinds_and_restores_previous_handler(self):
        previous = signal.getsignal(signal.SIGTERM)
        unwound = []

        def work():
            try:
                os.kill(os.getpid(), signal.SIGTERM)
            finally:
                unwound.append(True)

        with self.assertRaises(KeyboardInterrupt):
            run_cli(work)
        self.assertEqual(unwound, [True])
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous)

    def test_real_child_exit_status_and_timeout(self):
        result = execute([sys.executable, "-B", "-c", "print('actual stdout'); raise SystemExit(7)"])
        self.assertEqual(result.exit_status, 7)
        self.assertEqual(result.stdout.strip(), "actual stdout")
        result = execute([sys.executable, "-B", "-c", "import time; time.sleep(1)"], timeout=0.01)
        self.assertTrue(result.timed_out)
        self.assertIsNone(result.exit_status)


class StaticTests(LoggedTest):
    def test_real_cli_json_shape_is_preserved_in_artifact(self):
        doc = {"results": [{"check_id": "rules.escape-room-canary-mount",
                           "path": "configs/drift.yaml", "start": {"line": 3},
                           "extra": {"message": "unit-test fixture"}}],
               "errors": [], "paths": {"scanned": ["configs/secure.yaml", "configs/drift.yaml"]}}
        with patch("engine.static.shutil.which", return_value="semgrep"), \
                patch("engine.static.execute", return_value=command(1, doc)):
            result = scan(self.log)
        self.assertEqual(result.status, FAIL)
        artifact = self.log.directory / (self.log.run_id + ".semgrep.json")
        self.assertEqual(json.loads(artifact.read_text()), doc)
        finding = next(e for e in self.log.events if e["event_type"] == "semgrep_finding")
        self.assertEqual(finding["observed_evidence"]["line"], 3)

    def test_unavailable_semgrep_is_not_a_clean_scan(self):
        with patch("engine.static.shutil.which", return_value=None), patch("pathlib.Path.is_file", return_value=False):
            result = scan(self.log)
        self.assertFalse(result.available)
        self.assertEqual(result.status, INCONCLUSIVE)
        self.assertFalse(any(e["event_type"] == "semgrep_finding" for e in self.log.events))

    def test_errors_or_unscanned_targets_cannot_pass(self):
        for doc in ({"results": [], "errors": [{"message": "parse error"}], "paths": {"scanned": []}},
                    {"results": [], "errors": [], "paths": {"scanned": []}}):
            with patch("engine.static.shutil.which", return_value="semgrep"), \
                    patch("engine.static.execute", return_value=command(0, doc)):
                self.assertEqual(scan(self.log).status, INCONCLUSIVE)

    def test_sample_verification_requires_both_rules_and_no_secure_findings(self):
        unsafe = [{"path": "configs/drift.yaml", "check_id": "rules." + rule}
                  for rule in ("escape-room-collector-network", "escape-room-canary-mount")]
        self.assertEqual(verify_samples(self.log, Scan(True, FAIL, unsafe)), PASS)
        self.assertEqual(verify_samples(self.log, Scan(True, FAIL, unsafe[:1])), FAIL)
        self.assertEqual(verify_samples(self.log, Scan(True, FAIL,
                         unsafe + [{"path": "configs/secure.yaml", "check_id": "bad"}])), FAIL)


if __name__ == "__main__":
    unittest.main()
