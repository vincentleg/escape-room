# Final two blockers

## ClickHouse diagnosis

The retained host receipts report HTTP 401. Local inspection confirms:

- `Settings.load()` reads only `.env.clickhouse`; exporting a different shell password does not override it.
- All six variables are present. TLS is enabled, port is 8443, and the endpoint has a ClickHouse Cloud hostname. The file is mode 0600.
- The loaded database username and password still match the old local backup. The password has no extra surrounding whitespace.
- The client sends the exact loaded values in `X-ClickHouse-User` and `X-ClickHouse-Key` over verified HTTPS, not in a URL or command argument. These are [officially supported authentication headers](https://clickhouse.com/docs/concepts/features/interfaces/http#authentication).

No missing-variable, quoting or header-format defect was found. The supplied credential pair is being rejected. HTTP 401 alone cannot determine whether the database password was changed or the saved pair belongs to a different service/user. No new authentication request was made during this fix.

**Corrective action:** replace the local SQL database username/password with the current pair for this exact existing Cloud service through the finishing command's hidden prompts. Do not use the Cloud account login or management API key. No manual configuration editing is required. Only the two credential fields are updated; the endpoint and other settings are preserved. Updates are atomic and mode 0600. Enter skips cloud verification; supplying the unchanged rejected pair is refused locally.

The next upload begins with a real SELECT 1. After any 401/403 or connection failure, the remaining cloud attempts in that execution are skipped. Ingestion requires the existing event-ID readback plus run-ID/count verification before a PASS receipt is produced.

## GitHub authorization and confirmation

The user's authorization is configured in the private local authorization file. Code enforces exactly `vincentleg/escape-room` and `create_incident_issue`, for sanitized evidence from verified recovered runs only. Other repository targets are rejected. Existing GitHub CLI authentication is used.

No first-publication confirmation has been recorded and no issue was created during this fix. The finishing command displays the exact sanitized report bodies, then requires typing `PUBLISH`. Declining or noninteractive input prevents publication. Confirmation is persisted separately from repository permission, so subsequent allowed runs do not prompt again. Existing duplicate-write protection and issue readback remain in place.

## One host command

```sh
/Users/vincentgppm/escape-room/scripts/finish_blockers.sh
```

This reuses the already verified recordings, including the genuine OpenAI result for run `14ebcce7…`. It never requests a new Docker drill or OpenAI call. It prompts for current ClickHouse SQL credentials and first-publication confirmation, attempts the two integrations, refreshes sanitized receipts, and uses the existing static build/deployment flow to update the linked Vercel production project. Failures remain explicitly INCONCLUSIVE; a successful deployment does not imply successful ingestion/publication.

Six focused local tests passed: exact header mapping and single-request 401 behavior, private credential replacement, unchanged-pair rejection, exact repository/action authority, required first confirmation/decline behavior, and no new Docker/OpenAI invocation. Shell syntax validation passed. No broad tests, frontend changes, service creation or new live success claims were made.
