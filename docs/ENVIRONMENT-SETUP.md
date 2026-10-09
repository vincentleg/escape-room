# Environment setup handoff

The empty `.env.clickhouse` was repaired from the project's existing `.env.clickhouse.save`, including its locally stored password. `CLICKHOUSE_DATABASE=default` fills the missing database setting. Both files are private (0600); `.gitignore` now excludes all `.env` files and backups except explicit `.example` templates. No credential was printed, placed in command arguments, sent to a tool/provider, or committed.

The password has **not** been authenticated: the actual `SELECT 1` request could not resolve the configured host. Do not interpret the repaired configuration as proof of a successful connection.

## Implemented

- `engine/clickhouse.py`: strict local configuration loading/repair and a standard-library HTTPS client. Passwords use headers, verified TLS is required for remote hosts, redirects are refused, and raw server error bodies are never logged.
- `engine/telemetry.py`: explicit upload of finalized demo/gate JSON evidence to `escape_room_events` in the existing database. There is no new database service or paid dependency.
- Uploaded rows retain run ID, event index, timestamp, phase, event type, status, source, observed evidence, configuration diff, original run status, verification scope, and artifact hash. Failed/inconclusive runs remain failed/inconclusive; configuration-only checks remain labelled as such.
- Upload requires `SELECT 1`, table creation if absent, a synchronous insert, and exact event-ID readback. Stable event IDs with `ReplacingMergeTree` and `FINAL` make repeated uploads logically deduplicated. Unit-test/setup reports are rejected as telemetry inputs. Local artifacts remain intact on upload failure.
- 15 additional focused tests cover credentials, repairs, redirects, secret-safe errors, evidence validation, and mandatory server readback. All 53 tests passed, including the existing 38 Phase 1 tests. HTTP calls in these tests are doubles; they do not prove remote ingestion.

## Actual remaining blockers

The managed session has restricted network access and cannot request sandbox escalation:

- ClickHouse hostname resolution: `gaierror`, errno 8.
- `pypi.org` hostname resolution: `gaierror`, errno 8. Semgrep installation failed; no installed CLI or real findings are claimed.
- Connection to the existing Docker Desktop Unix socket: `PermissionError`, errno 1 (`EPERM`). The session cannot grant itself socket access or change its own filesystem/network permission profile.
- Two additional real `engine.demo` executions returned exit 2, `INCONCLUSIVE`, before any container creation.
- Upload of the genuine new demo artifacts returned exit 2 at the connection check. **No ClickHouse table creation or ingestion has been verified.**

Actual setup/diagnostic events are under `evidence/setup/`. The latest combined runtime/upload report is `evidence/setup/6b76398bcf594750b2522dfd1e746a0d.json`; the repaired-configuration/SELECT attempt is `evidence/setup/97a84481401c4032b1157556b89f7315.json`. Prior Phase 1 evidence remains in `evidence/recorded/`.

## Resume when session access is available

The next agent needs permission to reach the local Docker Unix socket and outbound DNS/HTTPS to the existing ClickHouse host, Python package index, and Docker image registry if the image is not cached. No configuration editing or password resubmission should be necessary unless authentication subsequently fails.

Run the existing Semgrep installation and strict two-run verification, then use `engine.telemetry upload` with the two newly generated artifact paths. `engine.telemetry verify` performs the real `SELECT 1` separately. These commands are for the agent to execute; the user does not need to run troubleshooting commands.

References: [ClickHouse HTTP headers and inserts](https://clickhouse.com/integrations/nodejs), [ClickHouse HTTP authentication headers](https://clickhouse.com/blog/replica-aware-routing-public-beta), and [ReplacingMergeTree deduplication and FINAL](https://clickhouse.com/resources/engineering/clickhouse-optimize-table-final).
