"""Upload genuine demo/gate artifacts to an existing ClickHouse service."""

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from .clickhouse import ClickHouseError, Client, Settings, repair_settings
from .events import INCONCLUSIVE, PASS, ROOT, STATUSES, EventLog

TABLE = "escape_room_events"
DDL = """
CREATE TABLE IF NOT EXISTS escape_room_events
(
    event_id String,
    run_id String,
    event_index UInt32,
    timestamp DateTime64(3, 'UTC'),
    phase LowCardinality(String),
    event_type LowCardinality(String),
    status LowCardinality(String),
    source LowCardinality(String),
    observed_evidence String,
    config_diff String,
    run_status LowCardinality(String),
    verification_scope LowCardinality(String),
    artifact_sha256 String
)
ENGINE = ReplacingMergeTree
ORDER BY (run_id, event_id)
"""
FIELDS = {"run_id", "timestamp", "phase", "event_type", "status", "source",
          "observed_evidence", "config_diff"}
SECRET_KEYS = {"password", "clickhouse_password", "authorization", "x-clickhouse-key",
               "api_key", "access_token", "secret"}


def scrub(value, secret):
    if isinstance(value, str):
        return value.replace(secret, "<redacted>") if secret else value
    if isinstance(value, dict):
        return {key: "<redacted>" if key.lower() in SECRET_KEYS else scrub(item, secret)
                for key, item in value.items()}
    if isinstance(value, list):
        return [scrub(item, secret) for item in value]
    return value


def load_artifact(path, *, secret=""):
    """Accept only finalized Phase 1 demo/gate envelopes, never unit-test fixtures."""
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
        raise ClickHouseError("Telemetry artifact must be a regular JSON file under 16 MiB")
    raw = path.read_bytes()
    try:
        document = json.loads(raw)
        if not isinstance(document, dict) or document.get("schema_version") != 1:
            raise ValueError()
        run_id, events = document["run_id"], document["events"]
        if not re.fullmatch(r"[0-9a-f]{32}", run_id) or not isinstance(events, list) or not events:
            raise ValueError()
        summary = document["summary"]
        if not isinstance(summary, dict) or document["status"] not in STATUSES:
            raise ValueError()
        is_demo = events[0].get("event_type") == "run_started" and events[0].get("source") == "demo"
        is_gate = summary.get("command") == "gate"
        if summary.get("unit_test") or summary.get("scope") == "unit_tests_only" or not (is_demo or is_gate):
            raise ClickHouseError("Only genuine demo/gate artifacts are eligible; tests and setup reports are excluded")
        if (events[-1].get("event_type") != "run_completed"
                or events[-1].get("status") != document["status"]
                or events[-1].get("observed_evidence") != summary):
            raise ValueError()
        scope = "three_act_demo" if is_demo else summary.get("scope", "configuration_and_runtime")
        if scope not in {"three_act_demo", "configuration_and_runtime", "configuration_only"}:
            raise ValueError()
        digest = hashlib.sha256(raw).hexdigest()
        rows = []
        for index, event in enumerate(events):
            if not isinstance(event, dict) or set(event) != FIELDS or event["run_id"] != run_id:
                raise ValueError()
            if event["status"] not in STATUSES or not all(isinstance(event[k], dict) for k in ("observed_evidence", "config_diff")):
                raise ValueError()
            if not all(isinstance(event[k], str) and event[k] for k in ("phase", "event_type", "source")):
                raise ValueError()
            observed_at = datetime.fromisoformat(event["timestamp"])
            if observed_at.tzinfo is None:
                raise ValueError()
            clean = scrub(event, secret)
            # Stable across reuploads and independent of local path/password redaction.
            canonical = json.dumps(event, sort_keys=True, separators=(",", ":"))
            event_id = hashlib.sha256((str(index) + ":" + canonical).encode()).hexdigest()
            rows.append({"event_id": event_id, "run_id": run_id, "event_index": index,
                         "timestamp": observed_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                         "phase": clean["phase"], "event_type": clean["event_type"],
                         "status": clean["status"], "source": clean["source"],
                         "observed_evidence": json.dumps(clean["observed_evidence"], sort_keys=True),
                         "config_diff": json.dumps(clean["config_diff"], sort_keys=True),
                         "run_status": document["status"], "verification_scope": scope,
                         "artifact_sha256": digest})
        return rows
    except (ValueError, KeyError, TypeError, AttributeError):
        raise ClickHouseError("Invalid or incomplete telemetry artifact") from None


def upload(client, path, log):
    rows = load_artifact(path, secret=client.settings.password)
    client.select_one()
    log.emit("TELEMETRY", "clickhouse_connection_verified", PASS, "clickhouse",
             {"query": "SELECT 1", "result": 1})
    client.query(DDL)
    log.emit("TELEMETRY", "telemetry_table_ready", PASS, "clickhouse", {"table": TABLE})
    payload = ("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n").encode()
    client.query("INSERT INTO escape_room_events FORMAT JSONEachRow", data=payload,
                 parameters={"async_insert": "0"})
    # Read back every event ID. An HTTP 200 alone is not a verified ingestion.
    result = client.query(
        "SELECT event_id FROM escape_room_events FINAL "
        "WHERE run_id = {run_id:String} AND artifact_sha256 = {artifact:String} "
        "FORMAT JSONEachRow",
        parameters={"param_run_id": rows[0]["run_id"], "param_artifact": rows[0]["artifact_sha256"]})
    try:
        actual = {json.loads(line)["event_id"] for line in result.splitlines() if line}
    except (ValueError, KeyError, TypeError):
        raise ClickHouseError("Invalid telemetry readback response") from None
    if actual != {row["event_id"] for row in rows}:
        raise ClickHouseError("Telemetry readback did not match uploaded event IDs; ingestion unverified")
    observed = {"table": TABLE, "artifact_run_id": rows[0]["run_id"],
                "artifact_sha256": rows[0]["artifact_sha256"],
                "events_verified": len(actual), "run_status": rows[0]["run_status"],
                "verification_scope": rows[0]["verification_scope"]}
    log.emit("TELEMETRY", "telemetry_ingestion_verified", PASS, "clickhouse", observed)
    return observed


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("repair", "verify", "upload"))
    parser.add_argument("artifacts", nargs="*")
    parser.add_argument("--evidence-dir", default=str(ROOT / "evidence/setup"))
    args = parser.parse_args(argv)
    log = EventLog(args.evidence_dir)
    status = INCONCLUSIVE
    try:
        if args.action == "repair":
            log.emit("SETUP", "clickhouse_configuration_repaired", PASS,
                     "local_configuration", repair_settings())
        else:
            client = Client(Settings.load())
            if args.action == "verify":
                log.emit("TELEMETRY", "clickhouse_select_one", PASS,
                         "clickhouse", client.select_one())
            else:
                if not args.artifacts:
                    raise ClickHouseError("Upload requires finalized demo/gate artifact paths")
                for artifact in args.artifacts:
                    upload(client, artifact, log)
        status = PASS
    except (ClickHouseError, OSError, KeyboardInterrupt) as exc:
        reason = str(exc) if isinstance(exc, ClickHouseError) else "Local I/O failure or interruption"
        log.emit("TELEMETRY", "telemetry_unverified", INCONCLUSIVE, "clickhouse", {"reason": reason})
    log.finish(status, scope="clickhouse_" + args.action, exit_code=0 if status == PASS else 2)
    return 0 if status == PASS else 2


if __name__ == "__main__":
    raise SystemExit(main())
