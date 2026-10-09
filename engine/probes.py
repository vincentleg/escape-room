"""Real child processes; FAIL means observed access, PASS means observed denial."""

import json
import uuid
from dataclasses import dataclass

from .events import FAIL, INCONCLUSIVE, PASS
from .policy import Config
from .runner import CANARY_PATH

NETWORK_SCRIPT = r'''
import errno, http.client, json, socket, sys
host, token = sys.argv[1:]
try:
    connection = http.client.HTTPConnection(host, 8080, timeout=3)
    connection.request('GET', '/probe/' + token)
    response = connection.getresponse()
    body = json.loads(response.read(4096))
    if response.status != 200 or body != {'collector_token': token}:
        raise ValueError('Unexpected collector response')
    print(json.dumps({'outcome': 'access', 'collector_token': token}))
    sys.exit(0)
except OSError as exc:
    denied = exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EACCES, errno.EPERM)
    print(json.dumps({'outcome': 'denied' if denied else 'error',
                      'errno': exc.errno, 'error_type': type(exc).__name__, 'error': str(exc)}))
    sys.exit(10 if denied else 20)
except Exception as exc:
    print(json.dumps({'outcome': 'error', 'error_type': type(exc).__name__, 'error': str(exc)}))
    sys.exit(20)
'''

SECRET_SCRIPT = r'''
import hashlib, json, sys
try:
    with open('/canary/synthetic.txt', 'rb') as source:
        content = source.read(4096)
    digest = hashlib.sha256(content).hexdigest()
    if digest != sys.argv[1]:
        print(json.dumps({'outcome': 'error', 'error': 'Canary digest mismatch'}))
        sys.exit(20)
    print(json.dumps({'outcome': 'access', 'sha256': digest, 'bytes_read': len(content)}))
    sys.exit(0)
except (FileNotFoundError, PermissionError) as exc:
    print(json.dumps({'outcome': 'denied', 'errno': exc.errno, 'error_type': type(exc).__name__}))
    sys.exit(10)
except Exception as exc:
    print(json.dumps({'outcome': 'error', 'error_type': type(exc).__name__, 'error': str(exc)}))
    sys.exit(20)
'''


@dataclass(frozen=True)
class ProbeResult:
    name: str
    status: str
    evidence: dict


@dataclass(frozen=True)
class ProbeSet:
    network: ProbeResult
    secret: ProbeResult

    @property
    def status(self):
        statuses = {self.network.status, self.secret.status}
        if FAIL in statuses:
            return FAIL
        return PASS if statuses == {PASS} else INCONCLUSIVE

    def statuses(self):
        return {"network": self.network.status, "secret": self.secret.status}


def decode(result):
    if result.timed_out or result.error or result.exit_status not in (0, 10, 20):
        return {}
    try:
        data = json.loads(result.stdout)
        return data if isinstance(data, dict) else {}
    except ValueError:
        return {}


class Probes:
    def __init__(self, runner, log):
        self.runner, self.log = runner, log

    def network_attempt(self, config, phase):
        token = uuid.uuid4().hex
        result = self.runner.run_probe(config, NETWORK_SCRIPT,
                                       [self.runner.collector_ip, token], phase)
        data = decode(result)
        receipt = self.runner.collector_receipt(token, phase) if data.get("outcome") == "access" else None
        status = INCONCLUSIVE
        if result.exit_status == 0 and data.get("collector_token") == token and receipt:
            status = FAIL
        elif result.exit_status == 10 and data.get("outcome") == "denied" and data.get("errno") in (1, 13, 101, 113):
            # These are Linux errnos inside the Linux probe container, not host macOS errnos.
            status = PASS
        return ProbeResult("network", status,
                           {"command": result.evidence(), "probe": data,
                            "collector_receipt": receipt, "request_token": token})

    def positive_control(self, phase):
        result = self.network_attempt(Config(network="collector"), phase)
        ok = result.status == FAIL  # Actual access is required of the control.
        self.log.emit(phase, "collector_positive_control", PASS if ok else INCONCLUSIVE,
                      "runtime", result.evidence)
        return ok

    def network(self, config, phase):
        before = self.positive_control(phase)
        actual = self.network_attempt(config, phase)
        after = self.positive_control(phase)
        status = actual.status
        if status == PASS and not (before and after):
            status = INCONCLUSIVE
        evidence = {**actual.evidence, "positive_control_before": before,
                    "positive_control_after": after}
        self.log.emit(phase, "network_probe", status, "runtime", evidence)
        return ProbeResult("network", status, evidence)

    def secret(self, config, phase):
        # Validate existence, mount usability and exact content before interpreting absence.
        control_cmd = self.runner.run_probe(Config(mount_canary=True), SECRET_SCRIPT,
                                            [self.runner.canary_digest], phase)
        control = decode(control_cmd)
        control_ok = (control_cmd.exit_status == 0 and control.get("outcome") == "access"
                      and control.get("sha256") == self.runner.canary_digest)
        self.log.emit(phase, "canary_positive_control", PASS if control_ok else INCONCLUSIVE,
                      "runtime", {"command": control_cmd.evidence(), "probe": control})
        result = self.runner.run_probe(config, SECRET_SCRIPT, [self.runner.canary_digest], phase)
        data = decode(result)
        status = INCONCLUSIVE
        if result.exit_status == 0 and data.get("outcome") == "access" and data.get("sha256") == self.runner.canary_digest:
            status = FAIL
        elif (control_ok and result.exit_status == 10 and data.get("outcome") == "denied"
              and data.get("errno") in (2, 13)):
            status = PASS
        evidence = {"command": result.evidence(), "probe": data,
                    "positive_control": control_ok, "path": CANARY_PATH,
                    "synthetic_only": True, "expected_sha256": self.runner.canary_digest}
        self.log.emit(phase, "synthetic_secret_probe", status, "runtime", evidence)
        return ProbeResult("secret", status, evidence)

    def run(self, config, phase):
        probes = ProbeSet(self.network(config, phase), self.secret(config, phase))
        self.log.emit(phase, "probe_set_completed", probes.status, "runtime", probes.statuses())
        return probes
