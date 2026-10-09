"""Bounded argv execution. No shell and no model-generated commands."""

import os
import signal
import subprocess
import time
from dataclasses import asdict, dataclass

from .events import timestamp


@dataclass
class CommandResult:
    command: list
    started_at: str
    finished_at: str
    duration_ms: int
    exit_status: object
    stdout: str
    stderr: str
    timed_out: bool = False
    error: str = ""

    @property
    def ok(self):
        return self.exit_status == 0 and not self.timed_out and not self.error

    def evidence(self):
        return asdict(self)


def execute(command, timeout=30, *, env=None, cwd=None):
    started, clock = timestamp(), time.monotonic()
    code, out, err, timed_out, error = None, "", "", False, ""
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=timeout, env=env, cwd=cwd, check=False)
        code, out, err = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        out, err = exc.stdout or "", exc.stderr or ""
    except OSError as exc:
        error = str(exc)
    if isinstance(out, bytes):
        out = out.decode("utf-8", errors="replace")
    if isinstance(err, bytes):
        err = err.decode("utf-8", errors="replace")
    return CommandResult(list(command), started, timestamp(),
                         round((time.monotonic() - clock) * 1000), code,
                         out, err, timed_out, error)


def docker_env():
    # The runner pins a validated local unix endpoint explicitly.
    return {k: v for k, v in os.environ.items()
            if k not in {"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY",
                         "DOCKER_CERT_PATH", "DOCKER_API_VERSION"}}


def run_cli(main):
    """Let normal termination unwind Docker context managers like Ctrl-C."""
    def interrupted(signum, frame):
        raise KeyboardInterrupt

    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        return main()
    finally:
        signal.signal(signal.SIGTERM, previous)
