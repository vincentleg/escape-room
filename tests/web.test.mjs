// Explicit test fixtures, never copied to public evidence or shipped in web/dist.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { STATES, validateManifest, probeForFrame, validateIntegrations } from '../web/app.js';

function fixture() {
  const timestamp = '2026-10-09T18:00:00.000Z';
  return { schema_version: 1, generated_at: timestamp, runs: [{
    run_id: 'a'.repeat(32), source_sha256: 'b'.repeat(64), recorded_at: timestamp,
    containment_status: 'PASS', cleanup_complete: true, drift_gate_exit: 1, recovery_gate_exit: 0,
    semgrep_status: 'INCONCLUSIVE', frames: STATES.map((state, i) => ({ state, timestamp, event_index: [4, 6, 11, 12, 14, 19][i] })),
    probes: ['SECURE', 'DRIFT', 'RECOVERY'].flatMap((phase, phaseIndex) => ['network', 'secret'].map((kind, kindIndex) => ({
      kind, phase, status: phase === 'DRIFT' ? 'FAIL' : 'PASS', exit_status: phase === 'DRIFT' ? 0 : 10,
      outcome: phase === 'DRIFT' ? 'access' : 'denied', timestamp, event_index: [[1, 3], [8, 9], [16, 18]][phaseIndex][kindIndex],
      positive_controls: true, collector_receipt: true, content_verified: true,
      errno: phase === 'DRIFT' ? null : kind === 'network' ? 101 : 2
    })))
  }] };
}

test('absence of recordings remains unverified, regardless of claimed counts', () => {
  const data = validateManifest({ schema_version: 1, runs: [], verified_run_count: 99, mode: 'recorded' });
  assert.equal(data.mode, 'awaiting_evidence');
  assert.equal(data.verified_run_count, 0);
});
test('valid records preserve real statuses, source hash, and separate static status', () => {
  const data = validateManifest(fixture());
  assert.equal(data.runs[0].semgrep_status, 'INCONCLUSIVE');
  assert.equal(data.runs[0].probes[2].status, 'FAIL');
  assert.equal(data.cloud_ingestion, 'UNVERIFIED');
});
test('private and unexpected fields cannot enter exported evidence', () => {
  const raw = fixture();
  raw.password = 'DO-NOT-PUBLISH';
  raw.runs[0].command = 'DO-NOT-PUBLISH';
  raw.runs[0].probes[0].token = 'DO-NOT-PUBLISH';
  assert.ok(!JSON.stringify(validateManifest(raw)).includes('DO-NOT-PUBLISH'));
});
test('missing positive controls, timeout exits, and missing receipts are rejected', () => {
  for (const mutate of [
    p => { p.probes[0].positive_controls = false; },
    p => { p.probes[0].exit_status = 20; },
    p => { p.probes[2].collector_receipt = false; },
    p => { p.probes[3].content_verified = false; },
    p => { p.cleanup_complete = false; }
  ]) {
    const data = fixture(); mutate(data.runs[0]);
    assert.throws(() => validateManifest(data));
  }
});
test('replay cannot reorder states or reuse a run ID', () => {
  const data = fixture(); data.runs[0].frames[0].state = 'RECOVERED';
  assert.throws(() => validateManifest(data));
  const duplicate = fixture(); duplicate.runs.push(structuredClone(duplicate.runs[0]));
  assert.throws(() => validateManifest(duplicate));
});
test('pending remediation/verification frames never display an invented passing probe', () => {
  const run = validateManifest(fixture()).runs[0];
  for (const index of [1, 3, 4]) assert.equal(probeForFrame(run, index, 'network'), null);
  assert.equal(probeForFrame(run, 2, 'network').outcome, 'access');
  assert.equal(probeForFrame(run, 5, 'secret').outcome, 'denied');
});
test('all static DOM bindings exist, script is a module, and no raw HTML injection exists', async () => {
  const html = await readFile(new URL('../web/index.html', import.meta.url), 'utf8');
  const js = await readFile(new URL('../web/app.js', import.meta.url), 'utf8');
  const ids = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map(m => m[1]));
  for (const [, id] of js.matchAll(/\$\('([^']+)'\)/g)) assert.ok(ids.has(id), `Missing DOM id: ${id}`);
  assert.match(html, /src="\.\/app.js" type="module"/);
  assert.ok(!js.includes('innerHTML'));
  assert.ok(!js.includes('eval('));
});
test('checked-in public evidence validates and contains no synthetic successful fixture', async () => {
  const raw = JSON.parse(await readFile(new URL('../web/evidence.json', import.meta.url), 'utf8'));
  assert.doesNotThrow(() => validateManifest(raw));
  assert.ok(!JSON.stringify(raw).includes('UNIT_TEST'));
});

test('integration claims require bounded advice, matching counts and exact GitHub URLs', () => {
  const timestamp = '2026-10-09T18:00:00.000Z';
  const raw = {
    openai: { status: 'PASS', timestamp, validated: true, model: 'gpt-4o-mini', response_id: 'resp_UNIT_TEST', response_sha256: 'b'.repeat(64),
      mode: 'during_incident', recommended_action: 'restore_approved_configuration', violations: ['network_egress', 'canary_read'],
      summary: 'Both containment boundaries failed in the actual controlled probes.', api_key: 'PRIVATE_TEST' },
    clickhouse: { status: 'PASS', timestamp, readback_verified: true, select_one: 1, events_uploaded: 100, events_verified: 100, host: 'PRIVATE_TEST' },
    github: { status: 'PASS', timestamp, readback_verified: true, repository: 'test-owner/test-repo', issue_number: 1, issue_url: 'https://github.com/test-owner/test-repo/issues/1' }
  };
  assert.ok(Object.values(validateIntegrations(raw)).every(r => r.status === 'PASS'));
  assert.ok(!JSON.stringify(validateIntegrations(raw)).includes('PRIVATE_TEST'));
  raw.openai.recommended_action = 'arbitrary_shell';
  raw.clickhouse.events_verified = 99;
  raw.github.issue_url = 'javascript:alert(1)';
  assert.ok(Object.values(validateIntegrations(raw)).every(r => r.status === 'INCONCLUSIVE'));
});

test('commander records: recorded outcomes validate and contradictions are rejected', async () => {
  const { validateCommander } = await import('../web/commander.js');
  const raw = JSON.parse(await readFile(new URL('../web/commander.json', import.meta.url), 'utf8'));
  const data = validateCommander(raw);
  assert.deepEqual(data.scenarios.map(r => r.outcome), ['VERIFIED_SAFE', 'VERIFIED_SAFE', 'ESCALATED', 'RECURRENCE_BLOCKED']);
  const forged = structuredClone(raw);
  forged.scenarios[2].outcome = 'VERIFIED_SAFE';
  assert.throws(() => validateCommander(forged));
  const looping = structuredClone(raw);
  looping.scenarios[0].attempts = [{}, {}, {}];
  assert.throws(() => validateCommander(looping));
});
