"""Own only disposable, labelled resources on a local Docker daemon."""

import hashlib
import ipaddress
import json
import os
import re
import tempfile
import time
import uuid
from pathlib import Path

from .events import INCONCLUSIVE, PASS
from .policy import ConfigStore
from .process import docker_env, execute

IMAGE = "python:3.12-alpine"
LABEL = "io.escape-room.run-id"
CANARY_PATH = "/canary/synthetic.txt"
COLLECTOR = r'''
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime, timezone
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if not self.path.startswith('/probe/'):
            self.send_error(404)
            return
        token = self.path.removeprefix('/probe/')
        body = json.dumps({'collector_token': token}).encode()
        print(json.dumps({'event': 'collector_received', 'token': token,
                          'timestamp': datetime.now(timezone.utc).isoformat()}), flush=True)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
server = HTTPServer(('0.0.0.0', 8080), Handler)
print(json.dumps({'event': 'collector_ready'}), flush=True)
server.serve_forever()
'''


class InfrastructureError(RuntimeError):
    pass


class Runner:
    def __init__(self, log):
        self.log = log
        self.prefix = "escape-" + log.run_id
        self.network = self.prefix + "-net"
        self.collector = self.prefix + "-collector"
        self.base = ["docker"]
        self.resources = []
        self.cleanup_ok = True
        self.image_id = None
        self.collector_ip = None
        self.temporary = tempfile.TemporaryDirectory(prefix=self.prefix + "-")
        self.directory = Path(self.temporary.name).resolve()
        log.redact_path(self.directory, "<run-temp>")
        self.store = ConfigStore(self.directory)
        self.canary_dir = self.directory / "canary"
        self.canary_dir.mkdir(mode=0o755)
        content = "FAKE-ESCAPE-ROOM-CANARY-NOT-A-SECRET-" + uuid.uuid4().hex
        canary = self.canary_dir / "synthetic.txt"
        canary.write_text(content, encoding="ascii")
        canary.chmod(0o444)
        self.canary_digest = hashlib.sha256(content.encode()).hexdigest()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def command(self, args, phase="INFRASTRUCTURE", *, timeout=30,
                allowed_codes=(0,)):
        result = execute(self.base + args, timeout=timeout, env=docker_env())
        status = PASS if result.exit_status in allowed_codes and not (
            result.timed_out or result.error) else INCONCLUSIVE
        self.log.emit(phase, "command_completed", status, "docker", result.evidence())
        return result

    def require(self, args, *, timeout=30):
        result = self.command(args, timeout=timeout)
        if not result.ok:
            raise InfrastructureError("Docker command failed; see command_completed evidence")
        return result

    def setup(self):
        # Context lookup does not connect. Explicitly reject remote/public daemons.
        endpoint = os.environ.get("DOCKER_HOST")
        context_name = os.environ.get("DOCKER_CONTEXT")
        if context_name or not endpoint:
            args = ["context", "inspect", "--format", '{{json .Endpoints.docker.Host}}']
            args += [context_name] if context_name else []
            context = self.require(args)
            try:
                endpoint = json.loads(context.stdout)
                if not isinstance(endpoint, str):
                    raise ValueError("Invalid endpoint")
            except (KeyError, IndexError, TypeError, ValueError) as exc:
                raise InfrastructureError("Cannot determine Docker endpoint") from exc
        if not endpoint.startswith("unix:///"):
            raise InfrastructureError("Only local unix Docker sockets are allowed")
        self.base = ["docker", "--host", endpoint]
        self.require(["version", "--format", "{{json .Server}}"])
        image = self.command(["image", "inspect", IMAGE])
        if not image.ok:
            self.require(["pull", IMAGE], timeout=120)
            image = self.require(["image", "inspect", IMAGE])
        try:
            self.image_id = json.loads(image.stdout)[0]["Id"]
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", self.image_id):
                raise ValueError("Invalid image ID")
        except (ValueError, KeyError, TypeError, IndexError) as exc:
            raise InfrastructureError("Cannot pin local image ID") from exc
        self.log.emit("INFRASTRUCTURE", "image_pinned", PASS, "docker",
                      {"image": IMAGE, "image_id": self.image_id})
        self.resources.append(("network", self.network))
        self.require(["network", "create", "--driver", "bridge", "--internal",
                      "--label", LABEL + "=" + self.log.run_id, self.network])
        self.resources.append(("container", self.collector))
        self.require(["run", "--detach", "--rm", "--name", self.collector,
                      *self.restrictions(), "--network", self.network,
                      self.image_id, "python", "-u", "-c", COLLECTOR])
        result = self.require(["container", "inspect", self.collector])
        try:
            data = json.loads(result.stdout)[0]
            self.collector_ip = str(ipaddress.IPv4Address(
                data["NetworkSettings"]["Networks"][self.network]["IPAddress"]))
        except (KeyError, IndexError, ValueError, TypeError) as exc:
            raise InfrastructureError("Collector has no bridge IPv4 address") from exc
        self.log.emit("INFRASTRUCTURE", "collector_started", PASS, "docker",
                      {"network": self.network, "ip": self.collector_ip,
                       "port": 8080, "published_ports": [], "internal": True})
        for _ in range(10):
            ready = self.command(["logs", self.collector])
            if ready.ok and '"collector_ready"' in ready.stdout:
                return
            time.sleep(0.2)
        raise InfrastructureError("Collector did not become ready")

    def restrictions(self):
        return ["--label", LABEL + "=" + self.log.run_id,
                "--read-only", "--cap-drop", "ALL", "--security-opt",
                "no-new-privileges:true", "--user", "65534:65534",
                "--pids-limit", "64", "--memory", "64m", "--cpus", "0.5"]

    def run_probe(self, config, script, arguments, phase):
        if not self.image_id or not self.collector_ip:
            raise InfrastructureError("Runner is not ready")
        name = self.prefix + "-probe-" + uuid.uuid4().hex[:12]
        resource = ("container", name)
        self.resources.append(resource)
        args = ["run", "--rm", "--name", name, *self.restrictions(),
                "--network", "none" if config.network == "none" else self.network]
        if config.mount_canary:
            args += ["--mount", "type=bind,src=" + str(self.canary_dir) +
                     ",dst=/canary,readonly"]
        result = self.command(args + [self.image_id, "python", "-B", "-c", script,
                                      *arguments], phase, allowed_codes=(0, 10, 20))
        if not result.timed_out and not result.error and result.exit_status in (0, 10, 20):
            # docker run --rm has synchronously removed the completed container.
            self.resources.remove(resource)
        else:
            # A timed-out docker client may have left its container running.
            if self.remove_owned(*resource):
                self.resources.remove(resource)
            else:
                self.cleanup_ok = False
        return result

    def collector_receipt(self, token, phase):
        result = self.command(["logs", self.collector], phase)
        if not result.ok:
            return None
        try:
            entries = [json.loads(line) for line in result.stdout.splitlines() if line]
        except ValueError:
            return None
        return next((entry for entry in entries
                     if entry.get("event") == "collector_received"
                     and entry.get("token") == token), None)

    def remove_owned(self, kind, name):
        result = self.command([kind, "inspect", name], "CLEANUP")
        if not result.ok:
            # Missing is harmless. A daemon failure is not proof of cleanup.
            return (not result.timed_out and result.exit_status == 1 and
                    any(marker in result.stderr.lower()
                        for marker in ("no such container", "no such network", "no such object")))
        try:
            data = json.loads(result.stdout)[0]
            labels = data["Config"].get("Labels", {}) if kind == "container" else data.get("Labels", {})
        except (KeyError, IndexError, ValueError, TypeError):
            return False
        if (labels or {}).get(LABEL) != self.log.run_id:
            self.log.emit("CLEANUP", "ownership_mismatch", INCONCLUSIVE, "policy",
                          {"resource": name, "action": "refused_removal"})
            return False
        args = [kind, "rm"] + (["--force"] if kind == "container" else []) + [name]
        return self.command(args, "CLEANUP").ok

    def close(self):
        for kind, name in reversed(self.resources):
            if not self.remove_owned(kind, name):
                self.cleanup_ok = False
        self.resources.clear()
        self.temporary.cleanup()
        self.log.emit("CLEANUP", "cleanup_completed",
                      PASS if self.cleanup_ok else INCONCLUSIVE, "docker",
                      {"only_run_owned_resources": True, "complete": self.cleanup_ok})
