"""Bounded Responses API advice. The model has no tools or actuator access."""

import hashlib
import json
import os
import re
import shlex
import urllib.error
import urllib.request
from pathlib import Path

from .events import INCONCLUSIVE, PASS, ROOT, timestamp
from .policy import RESTORE_APPROVED


class IntegrationError(RuntimeError):
    """Only fixed, credential-safe messages may leave an integration boundary."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise IntegrationError("API redirect rejected")


def api_key():
    """Existing environment/project API keys only; never reuse OAuth login tokens."""
    key = os.environ.get("OPENAI_API_KEY", "").strip()
    if key:
        return key
    for path in (ROOT / ".env.openai", ROOT / ".env.local", ROOT / ".env"):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            lines = path.read_text().splitlines()
        except OSError:
            continue
        for line in lines:
            match = re.fullmatch(r"\s*(?:export\s+)?OPENAI_API_KEY\s*=\s*(.+)", line)
            if match:
                try:
                    parts = shlex.split(match[1], comments=True)
                except ValueError:
                    continue
                if len(parts) == 1 and parts[0].startswith("sk-"):
                    return parts[0]
    raise IntegrationError("OpenAI API key unavailable; a ChatGPT login is not an API key")


def private_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def incident_evidence(events):
    """Project actual observed access into fixed fields; no stdout, tokens or paths."""
    facts = []
    for event_type, boundary in (("network_probe", "network_egress"),
                                 ("synthetic_secret_probe", "canary_read")):
        matches = [e for e in events if e["phase"] == "DRIFT" and e["event_type"] == event_type]
        if len(matches) != 1:
            raise IntegrationError("Confirmed incident probe evidence is missing")
        event = matches[0]
        evidence = event["observed_evidence"]
        command, probe = evidence.get("command", {}), evidence.get("probe", {})
        if (event["status"] != "FAIL" or command.get("exit_status") != 0
                or command.get("timed_out") or command.get("error") or probe.get("outcome") != "access"):
            raise IntegrationError("Incident access was not genuinely observed")
        if boundary == "network_egress":
            token = evidence.get("request_token")
            verified = bool(token and probe.get("collector_token") == token
                            and (evidence.get("collector_receipt") or {}).get("token") == token)
        else:
            verified = bool(probe.get("sha256") and probe["sha256"] == evidence.get("expected_sha256")
                            and probe.get("bytes_read", 0) > 0)
        if not verified:
            raise IntegrationError("Incident access lacks corroborating evidence")
        facts.append({"boundary": boundary, "observed": "access", "exit_status": 0,
                      "corroborated": True, "timestamp": event["timestamp"]})
    return {"scope": "Disposable local exercise; deliberately fake canary; controlled collector",
            "approved": {"network": "none", "mount_canary": False},
            "observations": facts, "allowed_actions": [RESTORE_APPROVED]}


def validate_advice(value):
    if not isinstance(value, dict) or set(value) != {"summary", "violations", "recommended_action"}:
        raise IntegrationError("Model response failed the recommendation schema")
    if value["recommended_action"] != RESTORE_APPROVED:
        raise IntegrationError("Model recommendation is not allowlisted")
    if (not isinstance(value["violations"], list) or len(value["violations"]) != 2
            or set(value["violations"]) != {"network_egress", "canary_read"}):
        raise IntegrationError("Model assessment does not match the observed boundaries")
    summary = value["summary"]
    if (not isinstance(summary, str) or not 20 <= len(summary) <= 900
            or not re.fullmatch(r"[A-Za-z0-9 .,;:!?'()_\-\n]+", summary)
            or re.search(r"sk-|password|bearer|token|api.key", summary, re.I)):
        raise IntegrationError("Model summary failed public-text validation")
    return {"summary": summary, "violations": list(value["violations"]),
            "recommended_action": RESTORE_APPROVED}


def analyze(events, run_id, *, mode="during_incident", key=None, opener=None, private_dir=None):
    facts = incident_evidence(events)
    key = key or api_key()
    schema = {"type": "object", "additionalProperties": False,
              "properties": {"summary": {"type": "string"},
                             "violations": {"type": "array", "items": {"type": "string", "enum": ["network_egress", "canary_read"]}},
                             "recommended_action": {"type": "string", "enum": [RESTORE_APPROVED]}},
              "required": ["summary", "violations", "recommended_action"]}
    request_body = {"model": "gpt-4o-mini", "store": False, "max_output_tokens": 400,
                    "instructions": "Assess this confirmed containment incident using only the supplied facts. Return a short public evidence-based explanation, the violated boundaries and the one allowed remediation. Use plain ASCII prose, no commands, URLs, identifiers or private data. No speculation about future catastrophes. You advise; deterministic policy owns execution.",
                    "input": json.dumps(facts, sort_keys=True),
                    "text": {"format": {"type": "json_schema", "name": "containment_advice", "strict": True, "schema": schema}}}
    request = urllib.request.Request("https://api.openai.com/v1/responses",
                                     data=json.dumps(request_body).encode(), method="POST",
                                     headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
    try:
        with (opener or urllib.request.build_opener(NoRedirect())).open(request, timeout=30) as response:
            raw = response.read(1024 * 1024 + 1)
            if response.status != 200 or len(raw) > 1024 * 1024:
                raise IntegrationError("Unexpected OpenAI response")
        document = json.loads(raw)
        # Preserve the actual response privately, including refusal/incomplete results.
        digest = hashlib.sha256(raw).hexdigest()
        private_json(Path(private_dir or ROOT / "evidence/private") / (run_id + "-openai-" + digest[:16] + ".json"),
                     {"received_at": timestamp(), "run_id": run_id, "input": facts, "response": document})
        if document.get("status") != "completed" or not re.fullmatch(r"resp_[A-Za-z0-9_-]+", document.get("id", "")):
            raise IntegrationError("OpenAI response incomplete or unverified")
        output = [c["text"] for item in document.get("output", []) if item.get("type") == "message"
                  for c in item.get("content", []) if c.get("type") == "output_text"]
        if len(output) != 1:
            raise IntegrationError("OpenAI did not return one structured assessment")
        advice = validate_advice(json.loads(output[0]))
        return {"status": PASS, "timestamp": timestamp(), "mode": mode,
                "response_id": document["id"], "response_sha256": digest,
                "model": "gpt-4o-mini", "validated": True, **advice}
    except urllib.error.HTTPError as exc:
        code = exc.code
        exc.close()
        suffix = " (quota or rate limit; no credits purchased)" if code == 429 else ""
        raise IntegrationError("OpenAI HTTP %d%s" % (code, suffix)) from None
    except (urllib.error.URLError, OSError, TimeoutError):
        raise IntegrationError("OpenAI connection or local response storage unavailable") from None
    except (ValueError, KeyError, TypeError):
        raise IntegrationError("OpenAI response could not be validated") from None


def advise_incident(log):
    try:
        result = analyze(log.events, log.run_id)
        log.emit("AGENT", "openai_incident_analysis", PASS, "openai", result)
        return result["recommended_action"]
    except IntegrationError as exc:
        log.emit("AGENT", "openai_analysis_unverified", INCONCLUSIVE, "openai", {"reason": str(exc)})
        return None
