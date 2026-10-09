# ESCAPE ROOM — Submission Kit

**Title:** ESCAPE ROOM — Autonomous Containment & Recovery for AI Agents
**Tagline:** Before an AI agent escapes, prove you can contain it.

- Live site: https://escape-room-xi-jade.vercel.app
- GitHub: https://github.com/vincentleg/escape-room
- Incident reports filed by the agent: [issue #1](https://github.com/vincentleg/escape-room/issues/1) · [issue #2](https://github.com/vincentleg/escape-room/issues/2)

## Description (≈80 words)

ESCAPE ROOM is a fire drill for AI agents. It puts an agent in a disposable Docker sandbox, deliberately introduces configuration drift (network egress and a mounted secret canary), and **proves** the breach with real probes. A deterministic recovery agent then restores the approved configuration on its own, reruns the same probes in fresh containers, and declares recovery only after the boundary holds again. Semgrep catches the drift statically. OpenAI explains the incident. ClickHouse stores the audit trail. A GitHub issue publishes the report.

## 30-second pitch

"Companies are giving AI agents shell access, network access and secrets. When the sandbox config drifts, how do you know the agent can't escape, and who puts it back? ESCAPE ROOM runs a controlled containment drill. It breaks the boundary on purpose, proves the agent really reached the network and really read a secret, then restores the approved config by itself and re-tests. It only reports 'safe' when the same probes fail again. Every step leaves a receipt: Semgrep findings, an OpenAI analysis, 163 events in ClickHouse, and a GitHub incident report. Don't trust containment. Prove it."

## 3-minute demo script

| Time | Screen | Say |
|---|---|---|
| 0:00–0:15 | Hero | Agents get tools, network and secrets. Configs drift. Nobody rehearses the escape. |
| 0:15–0:25 | Chamber; point at "RECORDED VERIFICATION / NOT LIVE EXECUTION" | "These are real Docker drills recorded on my laptop today. The public site never controls a runtime." |
| 0:25–1:05 | Click **LAUNCH CRISIS**, let it play to **VERIFIED SAFE** | Probes denied, then drift. The collector really received a request and the canary was really read. The agent restores the approved config and runs the same probes again. Point at the OpenAI, ClickHouse and GitHub receipts. |
| 1:05–1:35 | Scroll to **Incident Commander**, **STANDARD BREACH** | The decision engine: observed facts, CRITICAL severity, root cause, candidate actions. Three unsafe actions are rejected with reasons. "The model advises; the allowlist decides." |
| 1:35–2:10 | Click **FAILED VERIFICATION** | The first fix didn't work. The network probe still reached the collector. The agent doesn't claim success. It diagnoses a persistent override layer, refuses to repeat the same action, quarantines the run-owned layer and re-verifies. Two attempts, capped. |
| 2:10–2:30 | Click **OUT OF AUTHORITY** | Same symptom, but the layer isn't owned by this run. Outcome: **RECOVERY FAILED — ESCALATED**. It stops, keeps the evidence and asks a human. |
| 2:30–2:50 | Click **REPEATED DRIFT**; show **Post-incident hardening** | The guard applied after recovery blocked the identical drift. The fingerprint matches the earlier incident. Click **Download regression rule**. It's a Semgrep rule verified to flag the incident config, with zero hits on the baseline. Marked RECOMMENDED; pushing it to CI is BLOCKED pending a human. |
| 2:50–3:00 | Back to top | "It knows when to act, when to stop, and how to keep it from happening again. ESCAPE ROOM." |

## Recording plan

1. Use Chrome in full screen at 1440p, zoom 100%, dark mode. Open the live URL and close any other tabs.
2. Record with QuickTime (File → New Screen Recording) or Cmd-Shift-5, with your mic on.
3. Do one dry run. Use the **1× speed** button: each stage lasts 2.4 s, so the full drill takes about 12 s. Click the timeline steps to pause on a stage while you talk.
4. Optional: cut to the GitHub issue tab and the terminal (`./scripts/verify_docker.sh` output already in `evidence/`). Do **not** rerun the drill on camera.

## Sponsor integrations (all verified with real receipts)

- **Semgrep:** custom rules in `rules/containment.yaml` (`escape-room-collector-network`, `escape-room-canary-mount`) statically flag unsafe sandbox configs. The real CLI found 2 drift findings per run and the secure sample is clean. The CI-style gate exits 1 during drift and 0 after recovery.
- **OpenAI:** `gpt-4o-mini` is called *during* the incident (run 14ebcce7, response `resp_03c5…`, SHA-256 recorded). Its output is validated against a strict schema: 2 violations and the allowlisted action. It is advisory only, and the deterministic safety engine keeps final remediation authority.
- **ClickHouse Cloud:** every engine event goes to the `escape_room_events` table. Run 76388a73 uploaded 80 events and run 14ebcce7 uploaded 83, for **163** events, all read back by event ID (SELECT 1, insert, readback, and run-count query).
- **GitHub:** after verified recovery, the agent files a sanitized incident report as an issue and reads it back (#1 and #2).
- **Docker / Vercel:** real disposable containers for the probes. The static public replay is hosted on Vercel.

## Architecture

```
configs/secure.yaml ─┐            ┌─ Semgrep rules (static drift detection)
configs/drift.yaml ──┴─► engine/runner.py ─► Docker sandbox + collector + canary probes (engine/probes.py)
                           │ state machine: SECURE → DRIFT → INCIDENT → REMEDIATING → VERIFYING → RECOVERED
                           ├─ engine/policy.py   allowlist: restore_approved_configuration only
                           ├─ engine/intelligence.py  OpenAI advisory analysis (validated, non-authoritative)
                           ├─ engine/gate.py     CI gate exit 1 / 0
                           ├─ engine/clickhouse.py  event upload + readback
                           └─ engine/integrations.py GitHub issue publish + readback
                                  ▼
             sanitized web/evidence.json (validated) ─► static site on Vercel (replay only)
```

## What is autonomous, deterministic, or prerecorded

- **Autonomous (local engine):** detecting drift, confirming exposure with probes, choosing and applying the remediation, retesting, cleaning up, and filing the GitHub report all happen with no human in the loop.
- **Deterministic:** the remediation is chosen by a fixed policy allowlist, not by the LLM. OpenAI advice is validated and must match the allowlisted action, and it can never execute commands.
- **Prerecorded:** the website **replays** two real recorded runs (sanitized, original timestamps, condensed timing). It is labeled "RECORDED REPLAY · NOT A LIVE EXECUTION". To run a live drill, use `./scripts/verify_docker.sh` locally with Docker.
- **Scope:** two controls (network egress, secret-canary read) against disposable local targets. This is not a universal sandbox certification.

## Incident Commander (added Oct 9 sprint)

`python -m engine.commander <standard|persistent|escalation|recurrence>` runs one scenario against disposable Docker (same Runner, probes and positive controls as the original drill). `python -m engine.commander export` writes the sanitized `web/commander.json`.

- **Decision engine (`engine/decision.py`):** deterministic. Inputs are probe outcomes, positive controls, active vs. effective config diff, override owner and attempt history. Outputs are facts, severity, classification, root cause plus evidence, candidate actions with allow/reject reasons, the selected action, and verification criteria. It never acts on uncorroborated evidence.
- **Allowlist:** `restore_approved_configuration` and `quarantine_run_override` (run-owned layers only; a layer owned outside the run raises `HumanApprovalRequired`). At most 2 remediation attempts, then escalation.
- **Recorded results (local Docker, Oct 9, cleanup verified on each):**
  - standard → VERIFIED SAFE (1 attempt).
  - persistent → restore did not fix it (network still FAIL); diagnosed override; quarantined; VERIFIED SAFE (2 attempts).
  - escalation → ESCALATED, network still FAIL, override removal BLOCKED for a human.
  - recurrence → after recovery the guard rejected the identical drift, probes still denied; RECURRENCE BLOCKED, fingerprint matches the standard run.
- **Prevention status meanings:**
  - APPLIED = a run-scoped admission guard, verified to reject the original drift.
  - RECOMMENDED = a Semgrep regression rule generated from the observed drift, verified locally to flag the incident config with 0 baseline false positives. It is not committed to CI.
  - BLOCKED = shared CI/policy changes, which need human approval.
- **Not done:** no OpenAI, ClickHouse or GitHub calls for commander runs; those receipts belong to the original two runs only. Fingerprint history is local evidence only.
