"""One read-only SELECT 1, no retry, with opt-in sanitized error diagnostics."""

import argparse
import base64
import html
import json
import re
import urllib.parse
from dataclasses import replace

from .clickhouse import ClickHouseError, Client, Settings


def sanitize_error(raw, status, settings):
    if len(raw) > 16384:
        return {"http_status": status, "cause_hint": "unknown", "sanitized_error_body": "Oversized error body withheld"}
    body = raw.decode("utf-8", errors="replace")
    # Decode common representations before redaction so escaped credentials cannot leak.
    for _ in range(2):
        body = html.unescape(urllib.parse.unquote(body))
    secrets = [settings.password, settings.user, settings.host,
               base64.b64encode((settings.user + ":" + settings.password).encode()).decode()]
    variants = set()
    for secret in secrets:
        variants.update((secret, json.dumps(secret)[1:-1], urllib.parse.quote_plus(secret)))
    for value in list(variants):
        for _ in range(2):
            value = html.unescape(urllib.parse.unquote(value))
            variants.add(value)
    for value in sorted(variants, key=len, reverse=True):
        if value:
            body = body.replace(value, "[redacted]")
    body = re.sub(r"(?is)<(script|style)\b[^>]*>.*?</\1>", " ", body)
    body = re.sub(r"<[^>]*>", " ", body)
    body = re.sub(r"https?://[^\s\"'<>]+", "[redacted-url]", body)
    body = re.sub(r"\b[\w.+-]+@[\w.-]+\b", "[redacted-email]", body)
    body = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[redacted-ip]", body)
    body = re.sub(r"\b(?:[a-fA-F0-9]{0,4}:){2,}[a-fA-F0-9:]+\b", "[redacted-ip]", body)
    body = re.sub(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9_+/=.-]+", r"\1 [redacted]", body)
    body = re.sub(r"\b(?:sk-|ghp_|github_pat_)[A-Za-z0-9_-]+", "[redacted]", body)
    body = " ".join("".join(c if c.isprintable() else " " for c in body).split())
    lower = body.lower()
    if re.search(r"ip.{0,100}(not allowed|not permitted|denied|blocked)|ip (access|allow) ?list|ip_allowlist", lower):
        hint = "ip_access_restriction_indicated"
    elif any(s in lower for s in ("authentication_failed", "authentication failed", "wrong password", "password is incorrect", "unknown user")):
        hint = "sql_credentials_rejected"
    elif any(s in lower for s in ("not enough privileges", "insufficient privileges", "required grant", "access_denied")):
        hint = "sql_authorization_indicated"
    elif "rbac: access denied" in lower:
        hint = "gateway_access_policy_possible_not_proven_ip_filter"
    elif any(s in lower for s in ("unknown_database", "unknown database", "cannot_modify_setting", "readonly")):
        hint = "database_or_query_configuration"
    elif status in (404, 405):
        hint = "endpoint_or_route_possible"
    else:
        hint = "unknown_do_not_infer_from_http_status_alone"
    match = re.search(r"\bCode:\s*(\d{1,6})\b", body)
    return {"http_status": status, "clickhouse_exception_code": int(match[1]) if match else None,
            "cause_hint": hint, "sanitized_error_body": body[:3000] or "Empty error body",
            "body_truncated": len(body) > 3000}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--default-user", action="store_true", help="Test the reset default SQL account for this request only; do not edit credentials")
    args = parser.parse_args(argv)
    client = None
    try:
        settings = Settings.load()
        if args.default_user:
            settings = replace(settings, user="default")
        client = Client(settings, diagnostics=True)
        result = client.select_one()
        print(json.dumps({"status": "PASS", **result, "default_user_override": args.default_user,
                          "settings_modified": False, "request_count": 1}, indent=2))
        return 0
    except ClickHouseError as exc:
        print(json.dumps({"status": "INCONCLUSIVE", "reason": str(exc),
                          "diagnostic": client.last_http_diagnostic if client else None,
                          "settings_modified": False, "retried": False}, indent=2))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
