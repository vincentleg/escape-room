"""Local Semgrep CLI only. No registry, cloud service, or invented findings."""

import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .events import FAIL, INCONCLUSIVE, PASS, ROOT
from .policy import DRIFT_PATH, SECURE_PATH
from .process import execute


@dataclass(frozen=True)
class Scan:
    available: bool
    status: str
    findings: list


def scan(log, paths=(SECURE_PATH, DRIFT_PATH)):
    cli = shutil.which("semgrep")
    if not cli and (ROOT / ".venv/bin/semgrep").is_file():
        cli = str(ROOT / ".venv/bin/semgrep")
    if not cli:
        log.emit("STATIC", "semgrep_unavailable", INCONCLUSIVE, "semgrep",
                 {"reason": "Semgrep CLI is not installed; static integration pending"})
        return Scan(False, INCONCLUSIVE, [])
    with tempfile.TemporaryDirectory(prefix="escape-semgrep-") as temporary:
        log.redact_path(temporary, "<semgrep-temp>")
        env = {**os.environ, "SEMGREP_SEND_METRICS": "off",
               "SEMGREP_ENABLE_VERSION_CHECK": "0",
               "SEMGREP_SETTINGS_FILE": str(Path(temporary) / "settings.yml"),
               "SEMGREP_LOG_FILE": str(Path(temporary) / "semgrep.log")}
        # Local rules and explicit samples. Findings intentionally return 1.
        result = execute([cli, "scan", "--config", "rules/containment.yaml",
                          "--json", "--metrics", "off", "--disable-version-check",
                          "--no-git-ignore", "--strict", "--error",
                          *[os.path.relpath(path, ROOT) for path in paths]],
                         timeout=120, env=env, cwd=str(ROOT))
    log.emit("STATIC", "semgrep_command", PASS if result.exit_status in (0, 1)
             and not result.timed_out and not result.error else INCONCLUSIVE,
             "semgrep", result.evidence())
    try:
        document = json.loads(result.stdout)
        findings = document["results"]
        scanned = {str((ROOT / path).resolve()) for path in document["paths"]["scanned"]}
        valid = (not result.timed_out and not result.error
                 and result.exit_status in (0, 1) and not document.get("errors")
                 and isinstance(findings, list)
                 and result.exit_status == (1 if findings else 0)
                 and all(isinstance(f, dict) and isinstance(f.get("check_id"), str)
                         and isinstance(f.get("path"), str)
                         and isinstance(f.get("start"), dict)
                         and isinstance(f["start"].get("line"), int)
                         and isinstance(f.get("extra"), dict)
                         and isinstance(f["extra"].get("message"), str) for f in findings)
                 and {str(Path(path).resolve()) for path in paths}.issubset(scanned))
        if not valid:
            raise ValueError("Semgrep failed or did not scan all requested files")
    except (ValueError, KeyError, TypeError) as exc:
        log.emit("STATIC", "semgrep_invalid_output", INCONCLUSIVE, "semgrep",
                 {"reason": str(exc)})
        return Scan(True, INCONCLUSIVE, [])
    artifact = log.directory / (log.run_id + ".semgrep.json")
    with artifact.open("x", encoding="utf-8") as stream:
        json.dump(log.sanitize(document), stream, indent=2)
        stream.write("\n")
    for finding in findings:
        log.emit("STATIC", "semgrep_finding", FAIL, "semgrep",
                 {"rule_id": finding["check_id"], "file": finding["path"],
                  "line": finding["start"]["line"],
                  "message": finding["extra"]["message"]})
    status = FAIL if findings else PASS
    log.emit("STATIC", "semgrep_scan_completed", status, "semgrep",
             {"findings": len(findings), "artifact": str(artifact)})
    return Scan(True, status, findings)


def verify_samples(log, result):
    if result.status == INCONCLUSIVE:
        return INCONCLUSIVE
    unsafe = [f for f in result.findings if Path(f["path"]).name == "drift.yaml"]
    safe = [f for f in result.findings if Path(f["path"]).name == "secure.yaml"]
    expected_ids = {"escape-room-collector-network", "escape-room-canary-mount"}
    detected = {f["check_id"].split(".")[-1] for f in unsafe}
    status = PASS if not safe and expected_ids <= detected else FAIL
    log.emit("STATIC", "semgrep_sample_verification", status, "semgrep",
             {"unsafe_findings": len(unsafe), "secure_findings": len(safe),
              "expected_rule_ids": sorted(expected_ids), "detected": sorted(detected)})
    return status
