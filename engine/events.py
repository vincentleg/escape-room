"""Append-only normalized events; persist evidence even when execution fails."""

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

PASS, FAIL, INCONCLUSIVE = "PASS", "FAIL", "INCONCLUSIVE"
STATUSES = {PASS, FAIL, INCONCLUSIVE}
ROOT = Path(__file__).resolve().parents[1]


def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class EventLog:
    def __init__(self, directory=None, *, echo=True):
        self.run_id = uuid.uuid4().hex
        self.directory = Path(directory or ROOT / "evidence")
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / (self.run_id + ".jsonl")
        self._file = self.path.open("x", encoding="utf-8")
        self.events = []
        self.echo = echo
        self.replacements = [(str(ROOT), "<workspace>"),
                             (str(Path.home()), "<home>")]

    def redact_path(self, path, replacement):
        self.replacements.insert(0, (str(path), replacement))

    def sanitize(self, value):
        if isinstance(value, str):
            for original, replacement in self.replacements:
                value = value.replace(original, replacement)
            return re.sub(r"unix://[^\s\"']+docker\.sock", "unix://<docker-socket>", value)
        if isinstance(value, dict):
            return {k: self.sanitize(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.sanitize(v) for v in value]
        return value

    def emit(self, phase, event_type, status, source, observed_evidence=None,
             config_diff=None):
        if status not in STATUSES:
            raise ValueError("Invalid event status")
        event = self.sanitize({
            "run_id": self.run_id, "timestamp": timestamp(), "phase": phase,
            "event_type": event_type, "status": status, "source": source,
            "observed_evidence": observed_evidence or {},
            "config_diff": config_diff or {},
        })
        self.events.append(event)
        line = json.dumps(event, sort_keys=True)
        self._file.write(line + "\n")
        self._file.flush()
        if self.echo:
            print(line, flush=True)
        return event

    def finish(self, status, **summary):
        self.emit("SUMMARY", "run_completed", status, "engine", summary)
        result = self.directory / (self.run_id + ".json")
        with result.open("x", encoding="utf-8") as stream:
            json.dump({"schema_version": 1, "run_id": self.run_id,
                       "status": status, "summary": self.sanitize(summary),
                       "events": self.events}, stream, indent=2)
            stream.write("\n")
        self._file.close()
        return result
