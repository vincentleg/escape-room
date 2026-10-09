"""Post-recovery integrations using real artifacts, explicit publication authority and readback."""

import argparse
import contextlib
import fcntl
import getpass
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from .clickhouse import ClickHouseError, Client, Settings
from .events import EventLog, INCONCLUSIVE, PASS, ROOT, timestamp
from .intelligence import IntegrationError, api_key, private_json, validate_advice
from .policy import RESTORE_APPROVED
from .telemetry import upload

RECEIPTS = ROOT / "evidence/integrations"
AUTHORIZATION = ROOT / ".escape-room-authorization.json"
REPOSITORY = r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*"
ALLOWED_REPOSITORY = "vincentleg/escape-room"


def valid_time(value):
    try:
        return isinstance(value, str) and datetime.fromisoformat(value).tzinfo is not None
    except ValueError:
        return False


def projection(run, document):
    """Public receipts are an explicit allowlist, bound to the actual source hash."""
    result = {key: {"status": INCONCLUSIVE} for key in ("openai", "clickhouse", "github")}
    if not isinstance(document, dict) or document.get("run_id") != run["run_id"] or document.get("source_sha256") != run["source_sha256"]:
        return result
    for name in result:
        value = document.get(name, {})
        if not isinstance(value, dict) or value.get("status") != PASS or not valid_time(value.get("timestamp")):
            continue
        if name == "openai":
            try:
                advice = validate_advice({k: value.get(k) for k in ("summary", "violations", "recommended_action")})
                if (value.get("validated") is not True or value.get("mode") not in ("during_incident", "recorded_incident_review")
                        or not re.fullmatch(r"resp_[A-Za-z0-9_-]+", value.get("response_id", ""))
                        or not re.fullmatch(r"[a-f0-9]{64}", value.get("response_sha256", ""))
                        or value.get("model") != "gpt-4o-mini"):
                    continue
                result[name] = {"status": PASS, "timestamp": value["timestamp"], "model": value["model"],
                                "mode": value["mode"], "response_id": value["response_id"],
                                "response_sha256": value["response_sha256"], "validated": True, **advice}
            except (IntegrationError, TypeError):
                continue
        elif name == "clickhouse":
            if (value.get("readback_verified") is True and value.get("select_one") == 1
                    and type(value.get("events_verified")) is int and value["events_verified"] > 0
                    and value.get("events_verified") == value.get("events_uploaded")):
                result[name] = {"status": PASS, "timestamp": value["timestamp"], "select_one": 1,
                                "readback_verified": True, "events_verified": value["events_verified"],
                                "events_uploaded": value["events_uploaded"], "table": "escape_room_events"}
        else:
            repo = value.get("repository", "")
            number = value.get("issue_number")
            if (isinstance(repo, str) and re.fullmatch(REPOSITORY, repo) and type(number) is int and number > 0
                    and value.get("readback_verified") is True
                    and value.get("issue_url") == "https://github.com/%s/issues/%d" % (repo, number)):
                result[name] = {"status": PASS, "timestamp": value["timestamp"], "repository": repo,
                                "issue_number": number, "issue_url": value["issue_url"], "readback_verified": True}
    return result


def receipts_for(run, events):
    path = RECEIPTS / (run["run_id"] + ".json")
    try:
        data = json.loads(path.read_text()) if path.is_file() else {}
    except (OSError, ValueError):
        data = {}
    result = projection(run, data)
    # Advice emitted by this run must precede deterministic acceptance/remediation.
    for index, event in enumerate(events):
        if event["event_type"] != "openai_incident_analysis" or event["status"] != PASS:
            continue
        accepted = any(e["event_type"] == "remediation_decision"
                       and e["observed_evidence"].get("model_recommendation_accepted") is True
                       and e["observed_evidence"].get("action") == RESTORE_APPROVED
                       for e in events[index + 1:])
        if accepted:
            candidate = projection(run, {"run_id": run["run_id"], "source_sha256": run["source_sha256"],
                                         "openai": event["observed_evidence"]})
            if candidate["openai"]["status"] == PASS:
                result["openai"] = candidate["openai"]
    return result


def authorize(repository):
    if repository != ALLOWED_REPOSITORY:
        raise IntegrationError("Incident publication is allowlisted only for vincentleg/escape-room")
    document = {"repository": repository, "action": "create_incident_issue",
                "scope": "one sanitized issue per verified recovered run", "authorized_at": timestamp()}
    if AUTHORIZATION.exists():
        existing = json.loads(AUTHORIZATION.read_text())
        if existing.get("repository") != repository or existing.get("action") != document["action"]:
            raise IntegrationError("Existing publication authorization names a different target")
        return existing
    else:
        private_json(AUTHORIZATION, document)
    return document


def publication_authority():
    try:
        value = json.loads(AUTHORIZATION.read_text())
        if (value.get("action") != "create_incident_issue" or value.get("repository") != ALLOWED_REPOSITORY
                or not valid_time(value.get("authorized_at")) or not valid_time(value.get("confirmed_at"))):
            raise ValueError()
        return value["repository"]
    except (OSError, ValueError, TypeError):
        raise IntegrationError("GitHub publication requires the exact repository/action allowlist and first-publication confirmation") from None


def confirm_publication(runs):
    """Confirmation is separate from the repository permission already granted."""
    document = authorize(ALLOWED_REPOSITORY)
    if valid_time(document.get("confirmed_at")):
        return True
    if not sys.stdin.isatty():
        print("GitHub INCONCLUSIVE: first-publication confirmation requires an interactive Terminal.")
        return False
    print("Publication preview: one sanitized incident issue per verified recovered run, ONLY in " + ALLOWED_REPOSITORY)
    for run in runs:
        title, body = issue_content(run)
        print("\n" + title + "\n" + body)
    if input("Confirm first publication and this per-run action by typing PUBLISH (anything else skips): ").strip() != "PUBLISH":
        print("GitHub publication not confirmed; no issue will be created.")
        return False
    document["confirmed_at"] = timestamp()
    temporary = AUTHORIZATION.with_suffix(".confirmed.tmp")
    private_json(temporary, document)
    temporary.replace(AUTHORIZATION)
    return True


def issue_content(run):
    # Never use model prose or raw command evidence in a public issue.
    title = "[ESCAPE ROOM] Verified containment recovery " + run["run_id"]
    body = ("ESCAPE_ROOM_RUN:" + run["run_id"] + "\n\n"
            "A deliberate local containment drill confirmed controlled collector access and synthetic canary readability. "
            "The autonomous engine restored its approved disposable configuration and verified that both probes were denied again.\n\n"
            "- Status: INCIDENT CONFIRMED → RECOVERED\n"
            "- Remediation: `" + RESTORE_APPROVED + "`\n"
            "- Incident timestamp: " + run["frames"][2]["timestamp"] + "\n"
            "- Verified recovery timestamp: " + run["frames"][5]["timestamp"] + "\n"
            "- Source artifact SHA-256: `" + run["source_sha256"] + "`\n"
            "- Sanitized evidence reference: `web/evidence.json`, run `" + run["run_id"] + "`\n"
            "- Drift gate: blocked; recovery gate: pass; disposable-resource cleanup: verified.\n\n"
            "This report was published automatically after validation of a completed recorded local run. "
            "It contains no credentials, canary contents or raw logs. It makes no universal sandbox-security claim.\n")
    return title, body


def gh(arguments, payload=None):
    executable = shutil.which("gh") or str(Path.home() / ".local/bin/gh")
    env = {k: v for k, v in os.environ.items() if k != "GH_DEBUG"}
    env.update(GH_PROMPT_DISABLED="1", GH_HOST="github.com")
    try:
        result = subprocess.run([executable, *arguments], input=json.dumps(payload) if payload is not None else None,
                                text=True, capture_output=True, timeout=30, env=env)
        if result.returncode:
            raise IntegrationError("GitHub request failed; check existing CLI authentication and connectivity")
        return json.loads(result.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        raise IntegrationError("GitHub CLI unavailable, timed out or returned invalid JSON") from None


def publish(run, prior, save_attempt):
    repository = publication_authority()  # Before any read or write to GitHub.
    title, body = issue_content(run)
    existing = gh(["issue", "list", "--repo", repository, "--state", "all", "--search",
                   "ESCAPE_ROOM_RUN:" + run["run_id"], "--limit", "100", "--json", "number,title,body"])
    matching = [issue for issue in existing if issue.get("title") == title and issue.get("body") == body]
    if matching:
        number = matching[0]["number"]
    else:
        if prior.get("github_attempted_at"):
            raise IntegrationError("Previous GitHub publication outcome uncertain; refusing a duplicate write")
        save_attempt()
        created = gh(["api", "--hostname", "github.com", "--method", "POST", "repos/" + repository + "/issues", "--input", "-"],
                     {"title": title, "body": body})
        number = created.get("number")
    if type(number) is not int or number < 1:
        raise IntegrationError("GitHub issue number unverified")
    verified = gh(["api", "--hostname", "github.com", "repos/%s/issues/%d" % (repository, number)])
    url = "https://github.com/%s/issues/%d" % (repository, number)
    if verified.get("html_url") != url or verified.get("title") != title or verified.get("body") != body or verified.get("pull_request"):
        raise IntegrationError("GitHub issue readback did not match the sanitized incident report")
    return {"status": PASS, "timestamp": timestamp(), "repository": repository,
            "issue_number": number, "issue_url": url, "readback_verified": True}


def ingest(path, run, log):
    client = Client(Settings.load())
    receipt = upload(client, path, log)
    text = client.query("SELECT run_id, count() AS events FROM escape_room_events FINAL "
                        "WHERE run_id = {run_id:String} AND artifact_sha256 = {artifact:String} "
                        "GROUP BY run_id FORMAT JSONEachRow",
                        parameters={"param_run_id": run["run_id"], "param_artifact": run["source_sha256"]})
    try:
        rows = [json.loads(line) for line in text.splitlines() if line]
        expected = len(json.loads(Path(path).read_text())["events"])
        if len(rows) != 1 or rows[0]["run_id"] != run["run_id"] or int(rows[0]["events"]) != expected or receipt["events_verified"] != expected:
            raise ValueError()
    except (ValueError, KeyError, TypeError):
        raise IntegrationError("ClickHouse run ID or event count did not match the actual artifact") from None
    return {"status": PASS, "timestamp": timestamp(), "events_uploaded": expected,
            "events_verified": expected, "readback_verified": True, "select_one": 1,
            "table": "escape_room_events"}


def process_artifact(path, *, cloud=True, github=True):
    from .replay import public_run
    run = public_run(path)  # Fails closed unless incident, recovery, gates and cleanup are proven.
    RECEIPTS.mkdir(parents=True, exist_ok=True)
    target = RECEIPTS / (run["run_id"] + ".json")
    with (RECEIPTS / (run["run_id"] + ".lock")).open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        document = json.loads(target.read_text()) if target.exists() else {}
        if document.get("source_sha256") != run["source_sha256"]:
            document = {"run_id": run["run_id"], "source_sha256": run["source_sha256"]}
        document["openai"] = run["integrations"]["openai"]
        log = EventLog(ROOT / "evidence/integration-events", echo=False)

        def save():
            temporary = target.with_suffix(".tmp")
            temporary.write_text(json.dumps(document, indent=2) + "\n")
            temporary.replace(target)

        def attempt():
            document["github_attempted_at"] = timestamp()
            save()  # An uncertain POST must never trigger an automatic duplicate issue.

        for name, enabled in (("clickhouse", cloud), ("github", github)):
            if not enabled or projection(run, document)[name]["status"] == PASS:
                continue
            try:
                document[name] = ingest(path, run, log) if name == "clickhouse" else publish(run, document, attempt)
                log.emit("INTEGRATION", name + "_verified", PASS, name,
                         {"artifact_run_id": run["run_id"], **document[name]})
            except (IntegrationError, ClickHouseError) as exc:
                document[name] = {"status": INCONCLUSIVE, "reason": str(exc)}
                log.emit("INTEGRATION", name + "_unverified", INCONCLUSIVE, name,
                         {"artifact_run_id": run["run_id"], "reason": str(exc)})
            except (OSError, ValueError, TypeError, KeyError):
                document[name] = {"status": INCONCLUSIVE, "reason": "Local integration receipt unavailable or invalid"}
            save()
        outcome = PASS if all(projection(run, document)[k]["status"] == PASS for k in ("openai", "clickhouse", "github")) else INCONCLUSIVE
        log.finish(outcome, artifact_run_id=run["run_id"])
        save()
        return document


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authorize-repository", help="Explicitly authorize one sanitized issue per verified recovered run in OWNER/REPO")
    parser.add_argument("--prompt-key", action="store_true")
    parser.add_argument("--new-drill", action="store_true", help="Run one new Docker drill with model advice during the actual incident")
    parser.add_argument("--deploy", action="store_true")
    parser.add_argument("--skip-cloud", action="store_true")
    parser.add_argument("--skip-github", action="store_true")
    parser.add_argument("--confirm-publication", action="store_true", help="Show sanitized reports and require confirmation before the first publication")
    args = parser.parse_args(argv)
    if args.authorize_repository:
        authorize(args.authorize_repository)
    key_available = False
    if args.new_drill or args.prompt_key:
        try:
            api_key()
            key_available = True
        except IntegrationError:
            if args.prompt_key and sys.stdin.isatty():
                key = getpass.getpass("Existing OpenAI API key (hidden; Enter skips; no credits will be purchased): ").strip()
                if key:
                    os.environ["OPENAI_API_KEY"] = key
                    key_available = True
    if (args.new_drill or args.prompt_key) and not key_available:
        print("OpenAI INCONCLUSIVE: no usable API key; no API request made.")
    from .replay import export_replay, public_run
    manifest = json.loads((ROOT / "web/evidence.json").read_text())
    selected_ids = {r["run_id"] for r in manifest["runs"]}
    paths = []
    for path in (ROOT / "evidence").rglob("*.json"):
        if path.stem in selected_ids:
            try:
                public_run(path)
                paths.append(path)
            except (RuntimeError, ValueError, KeyError):
                continue
    if args.new_drill and key_available:
        from .demo import main as demo
        directory = ROOT / "evidence/intelligent-drill"
        before = set(directory.glob("*.json"))
        print("Running one genuine Docker drill with bounded OpenAI advice...")
        private = ROOT / "evidence/private"
        private.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(private / ("drill-" + str(os.getpid()) + ".log"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream, contextlib.redirect_stdout(stream):
            code = demo(["--with-openai", "--require-semgrep", "--evidence-dir", str(directory)])
        print("New containment drill " + ("PASS" if code == 0 else "INCONCLUSIVE; original recordings preserved"))
        for path in set(directory.glob("*.json")) - before:
            if path.name.endswith(".semgrep.json"):
                continue
            try:
                public_run(path)
                paths.append(path)
            except (RuntimeError, ValueError, KeyError):
                continue
    if not paths:
        raise IntegrationError("No genuinely verified recovered artifacts available")
    if args.confirm_publication and not args.skip_github:
        args.skip_github = not confirm_publication([public_run(path) for path in dict.fromkeys(paths)])
    cloud_available = not args.skip_cloud
    for path in dict.fromkeys(paths):
        result = process_artifact(path, cloud=cloud_available, github=not args.skip_github)
        for name in ("openai", "clickhouse", "github"):
            value = result.get(name, {"status": INCONCLUSIVE})
            print(result["run_id"][:8], name, value["status"], value.get("issue_url", value.get("reason", "")))
        if result.get("clickhouse", {}).get("reason") in (
                "ClickHouse connection unavailable (network, DNS, TLS, or timeout)",
                "ClickHouse HTTP request failed (status 401)",
                "ClickHouse HTTP request failed (status 403)"):
            cloud_available = False
            print("ClickHouse connection/authentication blocked; remaining cloud attempts skipped for this execution.")
    exported = export_replay(paths)
    subprocess.run(["node", "scripts/build_site.mjs"], cwd=ROOT, check=True)
    verified_integrations = any(r["integrations"][k]["status"] == PASS for r in exported["runs"] for k in ("openai", "clickhouse", "github"))
    if args.deploy and not verified_integrations:
        print("Deployment skipped: no new integration has genuine verification yet; production unchanged.")
    if args.deploy and verified_integrations:
        link = json.loads((ROOT / ".vercel/project.json").read_text())
        if link.get("projectId") != "prj_O4zlIRaRWbNHW8WwoxAvUMnYJXn0" or link.get("orgId") != "team_J49jXmAXIjsAiupWY0z18yHN":
            raise IntegrationError("Deployment refused: expected existing Vercel project link")
        # Never pass a temporarily supplied API key to build/deployment subprocesses.
        env = {k: v for k, v in os.environ.items() if k not in ("OPENAI_API_KEY", "CLICKHOUSE_PASSWORD", "GH_TOKEN", "GITHUB_TOKEN")}
        subprocess.run(["npx", "--yes", "vercel@63.1.0", "deploy", "--prod", "--scope", "vincentleg"],
                       cwd=ROOT, env=env, check=True)
    complete = any(all(r["integrations"][k]["status"] == PASS for k in ("openai", "clickhouse", "github")) for r in exported["runs"])
    print("Integration report:", "PASS" if complete else "INCONCLUSIVE — see individual results; no simulated receipts")
    return 0 if complete else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (IntegrationError, OSError, ValueError, subprocess.SubprocessError):
        print("INCONCLUSIVE: local integration/deployment step unavailable; completed evidence preserved.", file=sys.stderr)
        raise SystemExit(2)
