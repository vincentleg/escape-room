# Final integration sprint

The existing visual design, two genuine Docker recordings, Semgrep evidence and Vercel project are preserved. The public site remains a static recorded replay, with no public API keys, Docker endpoint or cloud credentials.

## One host-side execution

Run from normal macOS Terminal, where Docker and network access are available:

```sh
/Users/vincentgppm/escape-room/scripts/finish_integrations.sh
```

This activates the existing virtualenv. If no existing `OPENAI_API_KEY` is found in the environment or local `.env.openai`, `.env.local` or `.env`, it prompts once with hidden input; Enter skips OpenAI. The key stays in process memory and is excluded from the deployment environment. Do not paste keys into chat. No purchases, credit top-ups, account upgrades or service creation are performed. OpenAI uses existing account access/credits; HTTP 429 remains unverified rather than triggering retries or a purchase.

With a key, the command runs one new genuine Docker drill so model advice occurs during an actual incident. It retains the two original artifacts and uploads their actual events, plus the new successful artifact if available, to the existing ClickHouse service. Optional failures do not erase local containment proof. A blocked cloud connection stops further cloud retries in that invocation.

GitHub remains disabled without explicit repository/action authorization. The agent asked for the exact target repository in this session. Once authorized, `.escape-room-authorization.json` records only that repository and permission to create one sanitized incident issue per verified recovered run. An explicit CLI alternative is adding `--authorize-repository OWNER/REPO` to the command above; **executing that option grants the narrowly described publication permission**. It does not authorize repository creation, pushes, comments or other actions. The existing authenticated `gh` CLI is used.

Successful integration receipts are merged into sanitized `web/evidence.json`, then the static site is rebuilt. If at least one new integration has genuine verified evidence, the command deploys to the existing linked `vincentleg / escape-room` Vercel project. It refuses an unexpected project/scope ID. If all integrations remain unverified, deployment is skipped and the current production site is unchanged. The Vercel CLI prints the actual production URL. No hackathon entry is submitted.

## What is implemented

- **OpenAI:** `engine/intelligence.py` sends only corroborated access observations, timestamps, the approved baseline and the action allowlist to `POST https://api.openai.com/v1/responses`. It uses `gpt-4o-mini`, strict JSON schema, a 400-token output limit, no tools and `store: false`. The model supplies a short evidence-based summary, two boundary violations and `restore_approved_configuration`. Independent local validation rejects commands, unknown actions, inconsistent boundaries and unsafe public text. The deterministic state machine always retains control and falls back to its existing approved restore when advice is unavailable or rejected. `python -m engine.demo --with-openai` enables this live incident hook.
- **API evidence:** the real response is saved privately with mode 0600 under `evidence/private/`; this directory is Git-ignored and excluded from deployment. Public output contains only a validated assessment, response ID, response digest, model, timestamp and action. A response is not counted merely because an HTTP request succeeded. Refusal/incomplete/schema failures remain unverified. No raw chain of thought is requested or exposed.
- **ClickHouse:** existing `SELECT 1`, synchronous insertion and exact event-ID readback are reused. An additional query verifies the original run ID and event count for the exact artifact digest. Only counts, table name, timestamp and verified receipt status reach the public site. Cloud success cannot be inferred from tests or configuration.
- **GitHub:** completed artifacts must pass the existing runtime proof validator (incident, recovery, gates, cleanup) before publication. The deterministic post-recovery handler generates a fixed sanitized issue body and creates it through the authenticated GitHub CLI. It reads the issue back and matches its repository, URL, title and body. A per-run lock, existing-issue lookup and persisted attempted-write marker prevent automatic duplicate publication after uncertain failures. No model-generated prose or commands enter the issue.
- **Public replay:** three compact sections expose OpenAI analysis at remediation and cloud/GitHub receipts at recovered. Each shows its own actual integration timestamp; later publication is not presented as part of an earlier Docker recording. Missing receipts show NOT VERIFIED. GitHub links are restricted to the verified repository/issue URL. Existing raw artifacts are never changed; the two most recent valid recordings are selected for display.

## Verified status in this implementation session

| Integration | Actual external execution |
| --- | --- |
| Docker / Semgrep | The two retained genuine recordings remain available and valid; no new Docker execution was attempted in the restricted session. |
| OpenAI | NOT VERIFIED: no API key found in the available environment/project files; no API call made. |
| ClickHouse | INCONCLUSIVE: one real upload attempt stopped at connection verification; connection unavailable (network, DNS, TLS or timeout). No ingestion claimed and no repeated troubleshooting. |
| GitHub | NOT VERIFIED: exact repository/action authorization pending. No issue created. |
| Updated production | Not deployed from this restricted session; existing production is unchanged. Host command performs deployment only after genuine integration verification. |

Targeted validation: 36 Python tests (integration boundaries, agent state machine, replay and ClickHouse) and 9 JavaScript tests passed. Test API/CLI responses are explicit doubles and are never public evidence.

## Three-minute demo

1. **0:00–0:25:** “AI incident readiness means rehearsing containment failures before they matter.” State the bounded scope: controlled network collector and a deliberately fake canary.
2. **0:25–1:15:** Start CRISIS DRILL. Explain that it replays a genuine local run. Show secure denial, deliberate drift and matching observed access evidence.
3. **1:15–1:50:** At remediation, show the genuine OpenAI assessment if verified. Explain the sole allowed action and deterministic authority. If missing, say it is unverified; do not imply the model directed an older run.
4. **1:50–2:20:** Show recovered denial and the security gate. Open the actual Semgrep findings and source lines.
5. **2:20–2:45:** Show verified ClickHouse counts and follow the real GitHub issue link if present. Explain that the local agent published after proof of recovery. Missing receipts must be described as pending.
6. **2:45–3:00:** Close with the production URL and authorized repository link. This is evidence for two tested controls, not universal sandbox security.

Record the screen and narration to produce the actual video; this outline is not a completed video artifact.

API implementation references: [OpenAI structured outputs](https://developers.openai.com/api/docs/guides/structured-outputs?api-mode=responses), [GitHub CLI API](https://cli.github.com/manual/gh_api), [GitHub issue lookup](https://cli.github.com/manual/gh_issue_list).
