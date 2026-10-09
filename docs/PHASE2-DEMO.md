# ESCAPE ROOM — submission-ready static interface

The public interface is implemented in `web/`: a responsive containment chamber, one-click **CRISIS DRILL**, six-state evidence replay, pause/reset/speed controls, probe ledger, actual Semgrep findings, local evidence import, and sanitized JSON download.

Positioning: **Autonomous Containment & Recovery for AI Agents**. Headline: **Before an AI agent escapes, prove you can contain it.**

## Fast path: local proof, no ClickHouse

Run from normal macOS Terminal:

```sh
/Users/vincentgppm/escape-room/scripts/verify_docker.sh
```

This activates the existing virtualenv, checks the local Docker daemon, attempts free Semgrep installation if absent, runs the real containment scenario twice, verifies actual custom-rule findings, and exports successful runtime evidence to `web/evidence.json`. Static-tool unavailability does not suppress Docker testing. A static-layer failure remains FAIL/INCONCLUSIVE in the report. Two runtime runs can be proven while Semgrep remains pending; the website labels those independently.

`scripts/local_verify.sh` also defaults to local verification now. ClickHouse requires explicit `--with-cloud`; optional cloud failure never invalidates or prevents local results. No cloud connection is attempted by the quick command or website. The existing integration and prior evidence are retained.

The exporter requires actual per-act probe outcomes, matching collector receipts, canary digest checks, positive controls, ordered state transitions, gate events, and cleanup. It publishes an allowlist of fields: no host paths, raw commands/stdout, canary contents, tokens, or credentials. Original local artifacts remain unchanged.

## Preview

```sh
cd /Users/vincentgppm/escape-room && npm run dev
```

Open `http://127.0.0.1:3000`. There are no npm dependencies or installation step. The preview serves only the static asset allowlist, never repository files. The verification exporter refreshes an existing `web/dist/evidence.json` as well; reload the page after verification. Alternatively, **Load a recording** accepts the sanitized `web/evidence.json` entirely inside the browser without uploading it.

Until a successful real run is exported, CRISIS DRILL opens an honest evidence-pending dialog. The UI does not animate a fictional recovered incident. Once the recording exists, the button plays only recorded states and probe results, with original timestamps. Replay pacing is intentionally condensed and labelled. Run IDs and source hashes are provenance aids, not third-party attestation.

## Free Vercel deployment preparation

The project is a static site suitable for a Vercel Hobby project. It has no server functions, databases, scheduled jobs, external APIs, analytics, or paid runtime dependencies. Use the existing root `vercel.json`:

- Framework: Other (`null`).
- Install command: empty / skipped.
- Build command: `node scripts/build_site.mjs`.
- Output directory: `web/dist`.
- Required environment variables: **none**. Never add ClickHouse credentials to Vercel.

Import the source project into Vercel, or deploy from a locally authenticated Vercel CLI with `vercel --prod`. This work prepares deployment; it does not create a Vercel account/project or claim a public URL. `.vercelignore` allows only the build helper and static source assets. The build itself copies a fixed static allowlist and revalidates/sanitizes evidence. A restrictive CSP permits only same-origin assets and evidence fetches.

Run local verification **before** the submission deployment so its genuine recording is included. If the site was already deployed, redeploy after `web/evidence.json` changes. Never ship `.env`, `.venv`, the Docker engine, raw evidence, or the repository root as the public directory.

## Validation and limits

Python tests cover proof validation, private-field exclusion, and preservation of local records. Node's built-in test runner checks public manifest validation, replay semantics, and DOM bindings without external dependencies. These fixtures are explicit unit doubles and are never published as evidence.

The build environment cannot bind a local preview port; browser rendering has not been verified here. The site has been prepared and built locally, not deployed. The genuine three-act proof still requires the user's normal Terminal because the managed session cannot access Docker. No Docker/DNS troubleshooting was retried for this phase.

Reference: [Vercel static build/output configuration](https://vercel.com/docs/project-configuration/vercel-json).
