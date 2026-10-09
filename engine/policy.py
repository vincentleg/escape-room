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
        self._write(APPROVED)

    def _write(self, config):
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(config.to_dict(), indent=2) + "\n")
        temporary.replace(self.path)

    def read(self):
        return load_config(self.path)

    def inject_drift(self, config):
        self._write(config)

    def remediate(self, action):
        if action != RESTORE_APPROVED:
            raise ValueError("Remediation is not allowlisted")
        self._write(APPROVED)
        return self.read()
