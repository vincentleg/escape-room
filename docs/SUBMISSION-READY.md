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
| 0:00–0:20 | Hero: "Before an AI agent escapes…" | The problem: agents get tools, network and secrets. Configs drift. Nobody rehearses the escape. |
| 0:20–0:35 | Scroll to the chamber; point at the "RECORDED VERIFICATION / NOT LIVE EXECUTION" bar | "This is a replay of a real Docker drill recorded on my laptop today, with the original timestamps. The public site never controls a runtime." |
| 0:35–0:45 | Click **LAUNCH CRISIS** | Banner: **SECURE**. Both probes are denied, and positive controls prove the probes themselves work. |
| 0:45–1:05 | **BREACH DETECTED → BREACH CONFIRMED** (flashing) | Drift: network on, canary mounted. The collector really received a request and the exact canary was really read. That's observed access, not a guess. |
| 1:05–1:30 | **CONTAINMENT**; OpenAI card appears | The agent has exactly one allowlisted action, restore_approved_configuration. GPT-4o-mini analyzed the incident live and recommended the same action. The deterministic engine keeps the final say, and the LLM has no shell access. |
| 1:30–1:50 | **AUTONOMOUS RECOVERY → VERIFIED SAFE** | Fresh containers, same probes, both denied again. The recovery gate passes and temporary resources are cleaned up. |
| 1:50–2:20 | **Final verdict panel** | Point at the incident-to-recovery time, the 2/2 probes, Semgrep PASS, OpenAI PASS, ClickHouse events read back, and the GitHub issue link. Click the issue. |
| 2:20–2:45 | Scroll to "Every claim has a record": probe ledger, Semgrep findings, run selector, Download evidence | Two independent recorded runs (76388a73 and 14ebcce7). Semgrep rules flag the drift config by file and line. The evidence is downloadable. |
| 2:45–3:00 | Back to top, then **↺ REPLAY CRISIS** | "Before an AI agent escapes, prove you can contain it. That's ESCAPE ROOM." |

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
