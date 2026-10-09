# Evidence artifacts

New runs write here by default. Generated JSON/JSONL is ignored by Git unless explicitly preserved under `recorded/`.

`recorded/` contains only actual commands executed in the build environment. **There is no successful Docker containment demonstration in this directory yet.** Docker socket access is denied and Semgrep installation is blocked by network/DNS access. Unit-test doubles are never copied here as runtime probe results.

For public replay, select a run whose summary explicitly has `three_acts_verified: true`, confirm the actual per-probe output and controls, and label the Semgrep layer separately if pending. Never animate a blocked or partial run as a recovered incident.

Path placeholders (`<workspace>`, `<home>`, `<docker-socket>`, `<run-temp>`, `<semgrep-temp>`) sanitize environment-specific locations. Probe tokens, image IDs, exit statuses, rule locations, and timestamps remain actual observations. A fixture or unit-test report is not containment proof.
