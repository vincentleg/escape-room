# Final submission audit

Audited 2026-10-09. **Not submission-ready.** Checklist is based on the requirements supplied in this conversation; the organizer's rules/submission URL has not been provided. No entry has been submitted.

PASS means observed evidence supports the requirement. FAIL means the current implementation does not satisfy it. NOT VERIFIED means the required external evidence or access is unavailable.

| Requirement | Status | Evidence / remaining blocker |
| --- | --- | --- |
| Vercel production website on free tier | NOT VERIFIED | No production URL obtained. A saved local Vercel login exists, but the authenticated account request failed at DNS resolution (`gaierror`, errno 8) in this restricted session. The Vercel connector was offered; no connection confirmation received. Account plan, deployment and public availability cannot yet be verified. No paid resources were created. |
| Public URL and browser playback | NOT VERIFIED | No deployed URL to test. Eight JavaScript tests pass, including replay semantics; these are not browser verification. |
| Public artifact excludes secrets and Docker control | PASS | Built output contains only five static assets. Checked against the locally stored ClickHouse password/host and Vercel token without printing them, plus private-key/token/path patterns: no matches. Build uses an explicit asset allowlist and sanitized evidence. No server functions or Docker endpoints. This verifies the local artifact, not an uninspected live deployment. |
| Live deployment excludes sensitive files | NOT VERIFIED | Requires deployment and HTTP verification. Never configure cloud credentials as public website variables. |
| Semgrep actually executed | PASS | Both runs include real Semgrep 1.136.0 JSON, zero scan errors, both secure/drift files scanned, two drift findings and zero secure findings. Rule IDs `rules.escape-room-collector-network` at `configs/drift.yaml:2` and `rules.escape-room-canary-mount` at `configs/drift.yaml:3`. |
| ClickHouse SELECT 1, ingestion and query-back | NOT VERIFIED | No successful connection or ingestion/readback event exists in the retained evidence. Latest successful local report explicitly skipped optional cloud checks. Earlier connection/upload attempts were INCONCLUSIVE; see details below. Code and unit doubles do not prove integration. |
| OpenAI real API integration and successful call | FAIL | No OpenAI API call implementation or successful response evidence found in the project. Codex-assisted development is not counted. No new billable API call was made. |
| Guild.ai integration (optional) | NOT VERIFIED | No implementation or genuine execution evidence found. Not counted. |
| At least three genuinely used sponsor tools | FAIL | **One proven: Semgrep.** ClickHouse, OpenAI and Guild.ai cannot be counted. Vercel deployment is also unverified; organizer eligibility for counting Vercel is unknown. |
| Autonomous action on the open web | FAIL | The agent autonomously restores local disposable Docker configuration. Its collector is on an internal Docker network. Neither local remediation nor recorded website playback proves an autonomous open-web action. |
| Functional demo with genuine evidence | PASS | Two completed Docker runs validate secure denial, actual drift collector receipt/canary read, automatic recovery, recovered denial, gate decisions and cleanup. Public records exactly match the validated exports of their original artifacts. Scope is only the two controlled probes, not universal sandbox security. |
| Automated tests and static build | PASS | Re-ran 60 Python tests and 8 JavaScript tests successfully during this audit. Static build succeeds with two genuine recordings. Docker itself was not rerun in this restricted session. |
| Final code in GitHub repository | NOT VERIFIED | No repository URL or remote established. Workspace has no `.git`; its filesystem policy prevents creation. The existing Phase 1 source bundle is an earlier snapshot, not proof that final Phase 2 code is published. GitHub connection offered, not confirmed. |
| Three-minute demo video | NOT VERIFIED | No video artifact or public video link supplied/found in the project. A playback UI is not a completed video. |
| Submission-ready links and description | FAIL | Description below is ready; production, GitHub, video and submission links remain missing. |
| Official hackathon eligibility/rules | NOT VERIFIED | Organizer rules URL needed to verify exact sponsor, open-web, deadline and submission criteria. |
| Submission held for user approval | PASS | No hackathon entry submitted. |

## Runtime and static evidence

The successful [local report](../evidence/local-verify/20261009T185013Z-a773c7eb210a/report.json) records both Docker demonstrations and custom Semgrep checks as PASS.

| Run | Original artifact | SHA-256 |
| --- | --- | --- |
| 1 | [f25697fdc9874adda887319fe075b7f4](../evidence/local-verify/20261009T185013Z-a773c7eb210a/demo-1/f25697fdc9874adda887319fe075b7f4.json) | `4ba7ec2ff77445c9b08084b1a49c4f01bd4115653256c693c63e0ecffad7c7cb` |
| 2 | [76388a73cc34463d9e77305c247973a9](../evidence/local-verify/20261009T185013Z-a773c7eb210a/demo-2/76388a73cc34463d9e77305c247973a9.json) | `ae06292bd96666f299162ed20a334572668c57dfc635e303c22f8c2d0d348758` |

Actual Semgrep JSON: [run 1](../evidence/local-verify/20261009T185013Z-a773c7eb210a/demo-1/f25697fdc9874adda887319fe075b7f4.semgrep.json), [run 2](../evidence/local-verify/20261009T185013Z-a773c7eb210a/demo-2/76388a73cc34463d9e77305c247973a9.semgrep.json). Sanitized public replay: [web/evidence.json](../web/evidence.json). Public replay explicitly labels cloud ingestion `UNVERIFIED` and execution as recorded.

## Exact ClickHouse verification gap

The [SELECT 1 attempt](../evidence/setup/97a84481401c4032b1157556b89f7315.json) and [telemetry attempt](../evidence/setup/7e029199d44846a9be17cfcc11b55138.json) contain INCONCLUSIVE events, reporting connection unavailable (network, DNS, TLS, or timeout). The earlier [normal-Terminal report](../evidence/local-verify/20261009T182839Z-5a7e2234f9c6/report.json) stopped at DNS/HTTPS with a generic error; it did not preserve the underlying exception. Consequently the exact normal-Terminal network/TLS root cause is **unknown**, not a proven password failure. Latest local verification deliberately skipped cloud checks. A successful real SELECT 1 plus insertion/readback is still required; no telemetry success is claimed. Per the deadline instruction, no further ClickHouse troubleshooting was attempted.

## Submission copy and links

**ESCAPE ROOM — Autonomous Containment & Recovery for AI Agents**

Before an AI agent escapes, prove you can contain it. ESCAPE ROOM detects deliberate sandbox configuration drift, confirms actual containment failures with a controlled network collector and a synthetic canary, restores an allowlisted baseline, and retests recovery automatically. Two genuine local Docker recordings back the public CRISIS DRILL replay. Custom Semgrep rules provide a separate static detection layer. The public interface replays recorded verification and exposes no Docker controls or credentials. Cloud telemetry and OpenAI integration are not yet verified/completed.

- Production URL: **NOT AVAILABLE — deployment blocked on authorized reachable Vercel access.**
- GitHub final-code URL: **NOT VERIFIED / not supplied.**
- Three-minute video URL: **NOT VERIFIED / not supplied.**
- Hackathon submission/rules URL: **NOT PROVIDED.**

The existing deployment configuration is ready: no npm dependencies, build `node scripts/build_site.mjs`, output `web/dist`, no environment variables required. Deployment must use a verified free/Hobby scope; no account upgrade is authorized. See [deployment preparation](PHASE2-DEMO.md).
