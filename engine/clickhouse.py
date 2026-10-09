"""Private local settings and a small, credential-safe ClickHouse HTTP client."""

import ipaddress
import json
import os
import re
import shlex
import ssl
import stat
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from .events import ROOT

ENV_PATH = ROOT / ".env.clickhouse"
ENV_KEYS = {"CLICKHOUSE_HOST", "CLICKHOUSE_PORT", "CLICKHOUSE_USER",
            "CLICKHOUSE_PASSWORD", "CLICKHOUSE_SECURE", "CLICKHOUSE_DATABASE"}
DEFAULTS = {"CLICKHOUSE_PORT": "8443", "CLICKHOUSE_USER": "default",
            "CLICKHOUSE_SECURE": "true", "CLICKHOUSE_DATABASE": "default"}


class ClickHouseError(RuntimeError):
    """Messages are fixed, never derived from HTTP bodies or credential values."""


def read_env(path):
    path = Path(path)
    if not path.exists():
        return {}
    if path.is_symlink() or not path.is_file():
        raise ClickHouseError("ClickHouse settings must be a regular local file")
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ClickHouseError("ClickHouse settings file must have owner-only permissions")
    values = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)", line)
        if not match or match[1] not in ENV_KEYS or match[1] in values:
            raise ClickHouseError("Invalid or duplicate ClickHouse setting on line %d" % number)
        raw = match[2].strip()
        if raw.startswith("\""):
            try:
                value, end = json.JSONDecoder().raw_decode(raw)
                if not isinstance(value, str) or (raw[end:].strip() and not raw[end:].lstrip().startswith("#")):
                    raise ValueError()
            except ValueError:
                raise ClickHouseError("Invalid quoted setting on line %d" % number) from None
        elif raw.startswith("'"):
            try:
                parts = shlex.split(raw, comments=True, posix=True)
            except ValueError:
                raise ClickHouseError("Invalid quoted setting on line %d" % number) from None
            if len(parts) != 1:
                raise ClickHouseError("Invalid quoted setting on line %d" % number)
            value = parts[0]
        else:
            value = re.split(r"\s+#", raw, maxsplit=1)[0].strip()
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ClickHouseError("Control characters are not allowed in ClickHouse settings")
        values[match[1]] = value
    return values


def placeholder(value):
    value = value.strip().lower().replace("-", "_")
    return (not value or value in {"password", "changeme", "change_me", "todo",
                                   "xxx", "xxxx", "...", "redacted"}
            or value.startswith(("your_", "paste_", "replace_", "<", "${")))


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    user: str = field(repr=False)
    password: str = field(repr=False)
    secure: bool = True
    database: str = "default"

    @classmethod
    def from_values(cls, values):
        missing = sorted(key for key in ENV_KEYS if not values.get(key))
        if missing:
            raise ClickHouseError("Missing configuration variables: " + ", ".join(missing))
        host = values["CLICKHOUSE_HOST"]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.\-]*", host):
            raise ClickHouseError("CLICKHOUSE_HOST must be a hostname, without scheme, path, or credentials")
        try:
            port = int(values["CLICKHOUSE_PORT"])
            if not 1 <= port <= 65535:
                raise ValueError()
        except ValueError:
            raise ClickHouseError("Invalid CLICKHOUSE_PORT") from None
        if values["CLICKHOUSE_SECURE"].lower() not in {"true", "false"}:
            raise ClickHouseError("CLICKHOUSE_SECURE must be true or false")
        secure = values["CLICKHOUSE_SECURE"].lower() == "true"
        if not secure:
            try:
                loopback = ipaddress.ip_address(host).is_loopback
            except ValueError:
                loopback = host == "localhost"
            if not loopback:
                raise ClickHouseError("Remote ClickHouse connections must use verified TLS")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", values["CLICKHOUSE_DATABASE"]):
            raise ClickHouseError("Invalid CLICKHOUSE_DATABASE identifier")
        if placeholder(values["CLICKHOUSE_PASSWORD"]):
            raise ClickHouseError("ClickHouse password is missing or a placeholder")
        for value in values.values():
            if any(ord(char) < 32 or ord(char) == 127 for char in value):
                raise ClickHouseError("Control characters are not allowed in ClickHouse settings")
        return cls(host, port, values["CLICKHOUSE_USER"], values["CLICKHOUSE_PASSWORD"],
                   secure, values["CLICKHOUSE_DATABASE"])

    @classmethod
    def load(cls, path=ENV_PATH):
        return cls.from_values(read_env(path))

    @property
    def url(self):
        return "%s://%s:%d/" % ("https" if self.secure else "http", self.host, self.port)


def repair_settings(path=ENV_PATH, backup=None):
    """Fill missing values from this project's existing local backup and env only."""
    path = Path(path)
    backup = Path(backup) if backup is not None else path.with_name(path.name + ".save")
    current = read_env(path)
    saved = read_env(backup)
    values, sources = {}, {}
    for key in ENV_KEYS:
        for source, candidate in (("current_file", current.get(key)),
                                  ("local_backup", saved.get(key)),
                                  ("environment", os.environ.get(key)),
                                  ("default", DEFAULTS.get(key))):
            if candidate and (key != "CLICKHOUSE_PASSWORD" or not placeholder(candidate)):
                values[key], sources[key] = candidate, source
                break
    Settings.from_values(values)  # Validate before touching the target.
    content = "# Local ClickHouse connection; credentials must never be committed.\n"
    content += "\n".join(key + "=" + json.dumps(values[key]) for key in sorted(ENV_KEYS)) + "\n"
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".env.clickhouse.repair-", delete=False) as stream:
            temporary = Path(stream.name)
            os.fchmod(stream.fileno(), 0o600)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return {"variables": sorted(values), "sources": sources, "mode": "0600"}


def update_credentials(user, password, path=ENV_PATH):
    """Replace only the explicitly supplied SQL credentials, without shell expansion."""
    path = Path(path)
    values = read_env(path)
    if user == values.get("CLICKHOUSE_USER") and password == values.get("CLICKHOUSE_PASSWORD"):
        raise ClickHouseError("Credentials unchanged; refusing to retry the rejected pair")
    values.update(CLICKHOUSE_USER=user, CLICKHOUSE_PASSWORD=password)
    Settings.from_values(values)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".env.clickhouse.update-", delete=False) as stream:
            temporary = Path(stream.name)
            os.fchmod(stream.fileno(), 0o600)
            stream.write("# Private SQL credentials for the existing ClickHouse service.\n")
            stream.write("\n".join(key + "=" + json.dumps(values[key]) for key in sorted(ENV_KEYS)) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward the password to another endpoint, even over HTTPS.
        raise ClickHouseError("ClickHouse redirect refused")


class Client:
    def __init__(self, settings, *, diagnostics=False):
        self.settings = settings
        self.diagnostics = diagnostics
        self.last_http_diagnostic = None
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirects(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()))

    def query(self, sql, *, data=None, parameters=None):
        # Authentication is in headers only, never argv, URL, or evidence.
        params = {"database": self.settings.database, "wait_end_of_query": "1",
                  "max_execution_time": "15"}
        params.update(parameters or {})
        if data is None:
            body = sql.encode("utf-8")
        else:
            params["query"] = sql
            body = data
        request = urllib.request.Request(
            self.settings.url + "?" + urllib.parse.urlencode(params), data=body,
            headers={"X-ClickHouse-User": self.settings.user,
                     "X-ClickHouse-Key": self.settings.password,
                     "Content-Type": "text/plain; charset=utf-8"}, method="POST")
        try:
            with self.opener.open(request, timeout=20) as response:
                payload = response.read(2 * 1024 * 1024 + 1)
                if response.status != 200 or len(payload) > 2 * 1024 * 1024:
                    raise ClickHouseError("Unexpected ClickHouse response")
        except urllib.error.HTTPError as exc:
            code = exc.code
            if self.diagnostics:
                from .clickhouse_diagnose import sanitize_error
                try:
                    self.last_http_diagnostic = sanitize_error(exc.read(16385), code, self.settings)
                except (OSError, ValueError):
                    self.last_http_diagnostic = {"http_status": code, "cause_hint": "unknown", "sanitized_error_body": "Error body unavailable"}
            exc.close()
            raise ClickHouseError("ClickHouse HTTP request failed (status %d)" % code) from None
        except (urllib.error.URLError, OSError, TimeoutError):
            raise ClickHouseError("ClickHouse connection unavailable (network, DNS, TLS, or timeout)") from None
        # Some streaming HTTP failures have status 200 but an exception body.
        if payload.startswith(b"Code:") or b"DB::Exception" in payload:
            raise ClickHouseError("ClickHouse returned a query error")
        try:
            return payload.decode("utf-8")
        except UnicodeError:
            raise ClickHouseError("Invalid ClickHouse response encoding") from None

    def select_one(self):
        if self.query("SELECT 1").strip() != "1":
            raise ClickHouseError("SELECT 1 did not return the expected value")
        return {"query": "SELECT 1", "result": 1, "verified": True}
