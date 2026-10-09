"""Strict configuration allowlist and a single permitted corrective action."""

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from .events import ROOT


@dataclass(frozen=True)
class Config:
    network: str = "none"
    mount_canary: bool = False

    def __post_init__(self):
        if self.network not in ("none", "collector"):
            raise ValueError("Only none and the private collector network are allowed")
        if type(self.mount_canary) is not bool:
            raise ValueError("mount_canary must be a boolean")

    def to_dict(self):
        return asdict(self)


APPROVED = Config()
SECURE_PATH = ROOT / "configs/secure.yaml"
DRIFT_PATH = ROOT / "configs/drift.yaml"
RESTORE_APPROVED = "restore_approved_configuration"
QUARANTINE_OVERRIDE = "quarantine_run_override"
ALLOWLISTED_ACTIONS = (RESTORE_APPROVED, QUARANTINE_OVERRIDE)


class AdmissionRejected(PermissionError):
    """The run-scoped guard refused a configuration that re-opens a known boundary."""


class HumanApprovalRequired(PermissionError):
    """The action touches a resource this run does not own."""


def load_config(path):
    # JSON is a supported YAML subset. No general YAML constructors or dependency.
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate configuration key: " + key)
            result[key] = value
        return result

    data = json.loads(Path(path).read_text(encoding="utf-8"),
                      object_pairs_hook=unique_pairs)
    if not isinstance(data, dict) or set(data) != {"network", "mount_canary"}:
        raise ValueError("Configuration must contain exactly network and mount_canary")
    return Config(**data)


def diff(config):
    return {key: {"approved": value, "observed": config.to_dict()[key]}
            for key, value in APPROVED.to_dict().items()
            if value != config.to_dict()[key]}


class ConfigStore:
    """An active configuration in this run's disposable directory only."""

    def __init__(self, directory):
        self.path = Path(directory) / "active.yaml"
        # Optional persistent layer applied on top of the active file, like a plugin
        # or startup hook that re-asserts settings. Absent by default.
        self.override_path = Path(directory) / "override.json"
        self.quarantine_dir = Path(directory) / "quarantine"
        self.guarded = {}
        self._write(APPROVED)

    def _write(self, config):
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(config.to_dict(), indent=2) + "\n")
        temporary.replace(self.path)

    def active(self):
        return load_config(self.path)

    def override(self):
        if not self.override_path.is_file():
            return None
        data = json.loads(self.override_path.read_text(encoding="utf-8"))
        if (set(data) != {"fields", "owner"} or data["owner"] not in ("run", "external")
                or not data["fields"] or not set(data["fields"]) <= {"network", "mount_canary"}):
            raise ValueError("Malformed override layer")
        return data

    def read(self):
        """Effective configuration: the active file plus any persistent override."""
        layer = self.override()
        active = self.active()
        return Config(**{**active.to_dict(), **layer["fields"]}) if layer else active

    def admits(self, config):
        return not any(config.to_dict()[key] == value for key, value in self.guarded.items())

    def inject_drift(self, config):
        if not self.admits(config):
            raise AdmissionRejected("Guard rejected a configuration matching a known incident")
        self._write(config)

    def inject_override(self, fields, owner="run"):
        merged = Config(**{**APPROVED.to_dict(), **fields})
        if not self.admits(merged):
            raise AdmissionRejected("Guard rejected an override matching a known incident")
        self.override_path.write_text(json.dumps({"fields": fields, "owner": owner}) + "\n")

    def enable_guard(self, changes):
        """Run-scoped prevention: refuse future writes that re-open these exact values."""
        self.guarded = {key: change["observed"] for key, change in changes.items()}
        return dict(self.guarded)

    def remediate(self, action):
        if action not in ALLOWLISTED_ACTIONS:
            raise ValueError("Remediation is not allowlisted")
        if action == RESTORE_APPROVED:
            self._write(APPROVED)
        else:
            layer = self.override()
            if layer is None:
                raise ValueError("No override layer to quarantine")
            if layer["owner"] != "run":
                raise HumanApprovalRequired("Override is not owned by this disposable run")
            self.quarantine_dir.mkdir(mode=0o700, exist_ok=True)
            self.override_path.replace(self.quarantine_dir / "override.json")
        return self.read()
