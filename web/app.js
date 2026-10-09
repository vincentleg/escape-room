export const STATES = ['SECURE', 'DRIFT_DETECTED', 'INCIDENT_CONFIRMED', 'REMEDIATING', 'VERIFYING', 'RECOVERED'];
const STATUS = new Set(['PASS', 'FAIL', 'INCONCLUSIVE']);
const PHASES = ['SECURE', 'DRIFT', 'RECOVERY'];
const finiteDate = value => typeof value === 'string' && Number.isFinite(Date.parse(value));
const assert = (condition, message) => { if (!condition) throw new Error(message); };

export function validateIntegrations(input = {}) {
  const result = Object.fromEntries(['openai', 'clickhouse', 'github'].map(name => [name, { status: 'INCONCLUSIVE' }]));
  if (!input || typeof input !== 'object') return result;
  const ai = input.openai;
  if (ai?.status === 'PASS' && ai.validated === true && finiteDate(ai.timestamp)
      && ai.model === 'gpt-4o-mini' && /^resp_[A-Za-z0-9_-]+$/.test(ai.response_id) && /^[a-f0-9]{64}$/.test(ai.response_sha256)
      && ['during_incident', 'recorded_incident_review'].includes(ai.mode)
      && ai.recommended_action === 'restore_approved_configuration'
      && Array.isArray(ai.violations) && ai.violations.length === 2 && new Set(ai.violations).size === 2
      && ai.violations.every(v => ['network_egress', 'canary_read'].includes(v))
      && typeof ai.summary === 'string' && ai.summary.length >= 20 && ai.summary.length <= 900
      && /^[A-Za-z0-9 .,;:!?'()_\-\n]+$/.test(ai.summary) && !/sk-|password|bearer|token|api.key/i.test(ai.summary)) {
    result.openai = { status: 'PASS', validated: true, timestamp: ai.timestamp, model: ai.model, response_id: ai.response_id,
      response_sha256: ai.response_sha256, mode: ai.mode, summary: ai.summary,
      violations: [...ai.violations], recommended_action: ai.recommended_action };
  }
  const ch = input.clickhouse;
  if (ch?.status === 'PASS' && finiteDate(ch.timestamp) && ch.readback_verified === true && ch.select_one === 1
      && Number.isSafeInteger(ch.events_verified) && ch.events_verified > 0 && ch.events_uploaded === ch.events_verified) {
    result.clickhouse = { status: 'PASS', timestamp: ch.timestamp, readback_verified: true, select_one: 1,
      events_verified: ch.events_verified, events_uploaded: ch.events_uploaded, table: 'escape_room_events' };
  }
  const gh = input.github;
  if (gh?.status === 'PASS' && finiteDate(gh.timestamp) && gh.readback_verified === true
      && /^[A-Za-z0-9][A-Za-z0-9_.-]*\/[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(gh.repository)
      && Number.isSafeInteger(gh.issue_number) && gh.issue_number > 0
      && gh.issue_url === `https://github.com/${gh.repository}/issues/${gh.issue_number}`) {
    result.github = { status: 'PASS', timestamp: gh.timestamp, readback_verified: true,
      repository: gh.repository, issue_number: gh.issue_number, issue_url: gh.issue_url };
  }
  return result;
}

// Public records are narrow projections, never raw engine stdout or credentials.
export function validateManifest(input) {
  assert(input && input.schema_version === 1 && Array.isArray(input.runs) && input.runs.length <= 2, 'Choose a sanitized web/evidence.json recording.');
  const runs = input.runs.map(run => {
    assert(/^[a-f0-9]{32}$/.test(run.run_id) && /^[a-f0-9]{64}$/.test(run.source_sha256), 'Recording provenance is missing.');
    assert(run.containment_status === 'PASS' && run.cleanup_complete === true && run.drift_gate_exit === 1 && run.recovery_gate_exit === 0, 'The recording does not prove recovery and cleanup.');
    assert(finiteDate(run.recorded_at) && STATUS.has(run.semgrep_status), 'Recording metadata is invalid.');
    assert(Array.isArray(run.frames) && run.frames.length === 6, 'The six recorded states are required.');
    let previousIndex = -1;
    let previousTime = -Infinity;
    const frames = run.frames.map((frame, index) => {
      assert(frame.state === STATES[index] && Number.isInteger(frame.event_index) && frame.event_index > previousIndex && finiteDate(frame.timestamp), 'The recorded event order is invalid.');
      assert(Date.parse(frame.timestamp) >= previousTime, 'The recorded timestamps are out of order.');
      previousIndex = frame.event_index;
      previousTime = Date.parse(frame.timestamp);
      return { state: frame.state, timestamp: frame.timestamp, event_index: frame.event_index };
    });
    assert(Array.isArray(run.probes) && run.probes.length === 6, 'All six actual probe results are required.');
    const ranges = { SECURE: [-1, frames[0].event_index], DRIFT: [frames[1].event_index, frames[2].event_index], RECOVERY: [frames[4].event_index, frames[5].event_index] };
    const probes = PHASES.flatMap(phase => ['network', 'secret'].map(kind => {
      const matches = run.probes.filter(probe => probe.phase === phase && probe.kind === kind);
      assert(matches.length === 1, 'Duplicate or missing probe results.');
      const p = matches[0];
      const denied = phase !== 'DRIFT';
      assert(p.status === (denied ? 'PASS' : 'FAIL') && p.exit_status === (denied ? 10 : 0) && p.outcome === (denied ? 'denied' : 'access'), 'Probe outcomes are inconsistent.');
      assert(finiteDate(p.timestamp) && Number.isInteger(p.event_index), 'Probe timing is missing.');
      assert(p.event_index > ranges[phase][0] && p.event_index <= ranges[phase][1], 'Probe evidence must occur within its recorded act.');
      assert(!denied || p.positive_controls === true, 'Denial requires a verified positive control.');
      if (denied) assert((kind === 'network' ? [1, 13, 101, 113] : [2, 13]).includes(p.errno), 'A timeout cannot prove containment.');
      if (!denied) assert(kind === 'network' ? p.collector_receipt === true : p.content_verified === true, 'Access requires observed collector/canary evidence.');
      return { kind, phase, status: p.status, timestamp: p.timestamp, event_index: p.event_index,
        exit_status: p.exit_status, outcome: p.outcome, positive_controls: p.positive_controls === true,
        collector_receipt: p.collector_receipt === true, content_verified: p.content_verified === true,
        errno: Number.isInteger(p.errno) ? p.errno : null };
    }));
    const allowedRules = new Set(['escape-room-collector-network', 'escape-room-canary-mount']);
    const findings = (Array.isArray(run.findings) ? run.findings : []).filter(f => allowedRules.has(f.rule_id) && ['configs/drift.yaml', 'configs/secure.yaml'].includes(f.file) && Number.isInteger(f.line) && f.line > 0).map(f => ({ rule_id: f.rule_id, file: f.file, line: f.line }));
    return { run_id: run.run_id, source_sha256: run.source_sha256, recorded_at: run.recorded_at,
      containment_status: 'PASS', cleanup_complete: true, semgrep_status: run.semgrep_status,
      drift_gate_exit: 1, recovery_gate_exit: 0, frames, probes, findings, integrations: validateIntegrations(run.integrations) };
  });
  assert(new Set(runs.map(r => r.run_id)).size === runs.length, 'Recordings must have distinct run IDs.');
  const infrastructure = Object.fromEntries(['docker', 'cloud', 'semgrep'].map(key => [key, STATUS.has(input.infrastructure?.[key]) ? input.infrastructure[key] : 'INCONCLUSIVE']));
  return { schema_version: 1, mode: runs.length ? 'recorded' : 'awaiting_evidence',
    generated_at: finiteDate(input.generated_at) ? input.generated_at : null,
    verified_run_count: runs.length, runs, infrastructure,
    cloud_ingestion: runs.length && runs.every(run => run.integrations.clickhouse.status === 'PASS') ? 'VERIFIED' : 'UNVERIFIED',
    scope: 'Controlled collector reachability and synthetic canary readability only' };
}

export function probeForFrame(run, frameIndex, kind) {
  const phase = ({ 0: 'SECURE', 2: 'DRIFT', 5: 'RECOVERY' })[frameIndex];
  return phase ? run.probes.find(p => p.phase === phase && p.kind === kind) : null;
}

const COPY = [
  ['BASELINE VERIFIED', 'The boundary holds.', 'Both controlled probes were denied. Positive controls confirmed that the collector and canary were available.'],
  ['CONFIGURATION DRIFT', 'Something changed.', 'The approved configuration no longer matches. Network access and a canary mount were deliberately introduced in the local exercise.'],
  ['EXPOSURE OBSERVED', 'The incident is real.', 'The collector received the request. The exact synthetic canary was read. These are observed accesses, not inferred risks.'],
  ['ALLOWLISTED RESPONSE', 'Restore the boundary.', 'The autonomous agent enters remediation. Its only allowed action is to restore the approved disposable sandbox configuration.'],
  ['RECOVERY UNDER TEST', 'Trust the retest.', 'The approved configuration is restored. Fresh containers run the same probes; recovery is still pending at this recorded moment.'],
  ['RECOVERY VERIFIED', 'Contained. Proven.', 'Both probes were denied again with valid positive controls. The recovery gate passed and the run’s temporary resources were cleaned up.']
];

// Stage-readable narrative over the six recorded states. Decisions mirror the deterministic engine.
const STAGES = [
  ['SECURE', 'Agent: baseline probes denied → boundary holds.'],
  ['BREACH DETECTED', 'Agent: config ≠ approved baseline → open incident.'],
  ['BREACH CONFIRMED', 'Agent: collector reached + canary read → exposure proven.'],
  ['CONTAINMENT', 'Agent: allowlisted action → restore_approved_configuration.'],
  ['AUTONOMOUS RECOVERY', 'Agent: fresh containers → rerun the same probes.'],
  ['VERIFIED SAFE', 'Agent: both probes denied → recovery gate PASS → cleanup.']
];

function boot() {
  const $ = id => document.getElementById(id);
  const timeline = [...document.querySelectorAll('#timeline button')];
  let manifest = validateManifest({ schema_version: 1, runs: [] });
  let selected = 0, frame = 0, playing = false, started = false, speed = 1, timer = null, imported = false;
  let toastTimer = null;
  const currentRun = () => manifest.runs[selected];
  const clock = timestamp => new Date(timestamp).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const notice = message => {
    $('toast').textContent = message;
    $('toast').classList.add('visible');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => $('toast').classList.remove('visible'), 5000);
  };
  const stop = () => { clearTimeout(timer); timer = null; playing = false; };
  const text = (tag, value, className) => {
    const element = document.createElement(tag);
    element.textContent = value;
    if (className) element.className = className;
    return element;
  };

  function renderFeed(run) {
    const feed = $('event-panel');
    feed.replaceChildren();
    const lines = [];
    run.frames.slice(0, frame + 1).forEach(f => lines.push({ index: f.event_index, time: f.timestamp, message: f.state.replaceAll('_', ' ').toLowerCase() }));
    run.probes.filter(p => p.event_index <= run.frames[frame].event_index).forEach(p => lines.push({ index: p.event_index, time: p.timestamp,
      message: `${p.kind === 'network' ? 'collector' : 'canary'}: ${p.outcome} · exit ${p.exit_status}` }));
    lines.sort((a, b) => a.index - b.index).slice(-6).forEach(line => {
      const row = text('div', '', 'feed-row');
      const time = text('time', clock(line.time));
      time.dateTime = line.time;
      row.append(time, text('span', line.message));
      feed.append(row);
    });
    feed.scrollTop = feed.scrollHeight;
  }

  function renderFrame() {
    const run = currentRun();
    if (!run) return;
    const state = STATES[frame];
    $('chamber').dataset.state = state;
    $('scene-state-label').textContent = state.replaceAll('_', ' ');
    $('mission-counter').textContent = `${String(frame + 1).padStart(2, '0')} / 06`;
    $('status-kicker').textContent = COPY[frame][0];
    $('state-title').textContent = COPY[frame][1];
    $('state-description').textContent = COPY[frame][2];
    const banner = $('stage-banner');
    banner.hidden = !started;
    if ($('stage-name').textContent !== STAGES[frame][0]) { banner.classList.remove('pulse'); void banner.offsetWidth; banner.classList.add('pulse'); }
    $('stage-name').textContent = STAGES[frame][0];
    $('stage-decision').textContent = STAGES[frame][1];
    $('stage-replay').textContent = `RECORDED REPLAY · RUN ${run.run_id.slice(0, 8)} · NOT A LIVE EXECUTION`;
    renderVerdict(run);
    $('state-announcement').textContent = `Recorded state: ${state.replaceAll('_', ' ')}. ${COPY[frame][1]}`;
    $('recording-state').textContent = `RECORD ${run.run_id.slice(0, 8)} · ${clock(run.frames[frame].timestamp)}`;
    for (const kind of ['network', 'secret']) {
      const probe = probeForFrame(run, frame, kind);
      const className = probe ? probe.status === 'PASS' ? 'pass' : 'fail' : '';
      $(kind + '-status').textContent = probe ? probe.outcome === 'denied' ? 'DENIED' : 'ACCESS OBSERVED' : 'RETEST PENDING';
      $(kind + '-status').className = className;
      $(kind + '-dot').className = 'probe-indicator ' + className;
    }
    timeline.forEach((button, index) => {
      button.disabled = false;
      button.classList.toggle('active', index === frame);
      button.classList.toggle('done', index < frame);
      if (index === frame) button.setAttribute('aria-current', 'step');
      else button.removeAttribute('aria-current');
    });
    $('pause-button').disabled = !started || frame === 5;
    $('pause-button').textContent = playing ? 'Ⅱ Pause' : '▷ Resume';
    $('reset-button').disabled = false;
    $('replay-caption').textContent = frame === 5 ? 'RECOVERY PROVEN IN THIS RECORDING · NO LIVE EXECUTION' : 'CONDENSED REPLAY · ORIGINAL EVENT TIMESTAMPS PRESERVED';
    renderFeed(run);
    renderIntegrations(run);
  }

  function renderVerdict(run) {
    $('verdict').hidden = frame !== 5;
    if (frame !== 5) return;
    $('verdict-run').textContent = run.run_id.slice(0, 8);
    const i = run.integrations;
    const seconds = (Date.parse(run.frames[5].timestamp) - Date.parse(run.frames[2].timestamp)) / 1000;
    const items = [
      ['INCIDENT → RECOVERY', `${seconds.toFixed(1)}s`, true],
      ['DOCKER RETEST', '2 / 2 probes denied', true],
      ['SEMGREP', run.semgrep_status === 'PASS' ? `PASS · ${run.findings.length} drift finding(s)` : run.semgrep_status, run.semgrep_status === 'PASS'],
      ['OPENAI ANALYSIS', i.openai.status === 'PASS' ? `PASS · ${i.openai.model}` : 'Not used · deterministic only', i.openai.status === 'PASS'],
      ['CLICKHOUSE', i.clickhouse.status === 'PASS' ? `${i.clickhouse.events_verified} events read back` : 'Not verified', i.clickhouse.status === 'PASS'],
      ['GITHUB INCIDENT', i.github.status === 'PASS' ? `issue #${i.github.issue_number}` : 'Not verified', i.github.status === 'PASS', i.github.issue_url]
    ];
    $('verdict-grid').replaceChildren(...items.map(([label, value, ok, href]) => {
      const cell = document.createElement('div');
      const dd = text('dd', '', ok ? 'ok' : '');
      if (href) { const a = text('a', value + ' ↗'); a.href = href; a.target = '_blank'; a.rel = 'noopener noreferrer'; dd.append(a); }
      else dd.textContent = value;
      cell.append(text('dt', label), dd);
      return cell;
    }));
  }

  function renderIntegrations(run) {
    const integrations = run.integrations;
    for (const name of ['openai', 'clickhouse', 'github']) {
      const receipt = integrations[name];
      const badge = $(name + '-integration-status');
      const body = $(name + '-integration-body');
      body.replaceChildren();
      const visible = name === 'openai' ? frame >= 3 : frame === 5;
      badge.textContent = receipt.status === 'PASS' ? (visible ? 'VERIFIED · RECORDED' : 'RECEIPT AVAILABLE') : 'NOT VERIFIED';
      badge.className = receipt.status === 'PASS' && visible ? 'pass' : '';
      if (receipt.status !== 'PASS') {
        const pending = { openai: 'No verified OpenAI response for this run. Deterministic policy remains in control.',
          clickhouse: 'No verified cloud ingestion receipt for this run. Local evidence remains available.',
          github: 'No verified public issue for this run. Publication requires authorization for an exact repository.' };
        body.append(text('p', pending[name]));
        continue;
      }
      if (!visible) {
        body.append(text('p', name === 'openai' ? 'Advance to remediation to inspect the recorded recommendation.' : 'Advance to recovered to inspect the post-recovery receipt.'));
        continue;
      }
      if (name === 'openai') {
        body.append(text('p', receipt.summary), text('code', receipt.recommended_action),
          text('small', receipt.mode === 'during_incident' ? 'Advice requested during the actual incident; deterministic allowlist accepted it.' : 'Later review of recorded evidence; did not direct the original recovery.'));
        body.append(text('small', `${receipt.model} · ${receipt.response_id}`));
      } else if (name === 'clickhouse') {
        body.append(text('p', `${receipt.events_verified} / ${receipt.events_uploaded} events read back. Run ID and event IDs match the original artifact.`),
          text('small', 'Real SELECT 1, insert, event-ID readback and run-count query.'));
      } else {
        body.append(text('p', 'The local agent published a sanitized incident report after verified recovery, then read it back from GitHub.'));
        const link = text('a', `${receipt.repository} · issue #${receipt.issue_number} ↗`);
        link.href = receipt.issue_url;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        body.append(link);
      }
      body.append(text('small', `Integration observed ${new Date(receipt.timestamp).toLocaleString()}. This page is recorded playback.`));
    }
    $('clickhouse-proof').textContent = integrations.clickhouse.status === 'PASS' ? 'Ingestion verified · recorded' : 'Ingestion not verified';
  }

  function renderLedger() {
    const run = currentRun();
    $('verified-runs').replaceChildren(text('span', '', 'sr-only'), document.createTextNode(String(manifest.runs.length)), text('span', ' / 2'));
    $('docker-proof').textContent = run ? 'Runtime verified · recorded' : manifest.infrastructure.docker === 'PASS' ? 'Connected · recorded check' : 'Not verified';
    $('docker-indicator').classList.toggle('neutral', !run && manifest.infrastructure.docker !== 'PASS');
    $('semgrep-proof').textContent = run?.semgrep_status === 'PASS' ? 'Rules verified · recorded' : run?.semgrep_status === 'FAIL' ? 'Rule validation failed' : 'Pending verification';
    if (!run) return;
    const seconds = (Date.parse(run.frames[5].timestamp) - Date.parse(run.frames[2].timestamp)) / 1000;
    $('recovery-duration').replaceChildren(document.createTextNode(`${seconds.toFixed(1)}s`), text('span', ' incident → recovery'));
    $('gate-proof').replaceChildren(document.createTextNode('PASS'), text('span', ' after recovery'));
    $('gate-proof').className = 'pass';
    const body = $('probe-ledger');
    body.replaceChildren();
    PHASES.forEach((phase, index) => {
      const tr = document.createElement('tr');
      const heading = document.createElement('td');
      heading.append(text('span', String(index + 1).padStart(2, '0'), 'table-number'), document.createTextNode(phase));
      tr.append(heading);
      for (const kind of ['network', 'secret']) {
        const probe = run.probes.find(p => p.phase === phase && p.kind === kind);
        const td = document.createElement('td');
        const denied = probe.status === 'PASS';
        td.append(text('span', denied ? 'Denied · verified' : 'Access · observed', `result-chip ${denied ? 'pass' : 'fail'}`),
          text('span', `exit ${probe.exit_status} · ${denied ? 'positive control passed' : kind === 'network' ? 'collector receipt matched' : 'canary content matched'}`, 'result-detail'));
        tr.append(td);
      }
      const gate = document.createElement('td');
      gate.append(text('span', phase === 'DRIFT' ? 'BLOCKED' : 'PASS', phase === 'DRIFT' ? 'fail' : 'pass'), text('span', `gate exit ${phase === 'DRIFT' ? 1 : 0}`, 'result-detail'));
      tr.append(gate);
      body.append(tr);
    });
    $('provenance').textContent = `Recorded ${new Date(run.recorded_at).toLocaleString()} · Run ${run.run_id} · Source SHA-256 ${run.source_sha256}. Sanitized local evidence; not a third-party attestation.`;
    $('download-evidence').disabled = false;
    $('findings-body').replaceChildren();
    if (!run.findings.length) $('findings-body').append(text('p', 'No actual Semgrep findings are present in this recording. Static verification remains separate from runtime proof.'));
    run.findings.forEach(finding => {
      const row = text('div', '', 'finding-row');
      row.append(text('span', finding.rule_id), text('code', `${finding.file}:${finding.line}`));
      $('findings-body').append(row);
    });
    $('findings-status').textContent = run.semgrep_status === 'PASS' ? 'VERIFIED · SECURE SAMPLE CLEAN' : run.semgrep_status;
  }

  function useManifest(data) {
    stop();
    manifest = validateManifest(data);
    selected = Math.max(0, manifest.runs.length - 1);
    frame = 0;
    started = false;
    const selector = $('run-select');
    selector.replaceChildren();
    if (manifest.runs.length) {
      manifest.runs.forEach((run, index) => {
        const option = text('option', `Run ${index + 1} · ${run.run_id.slice(0, 8)}`);
        option.value = String(index);
        selector.append(option);
      });
      selector.value = String(selected);
      selector.disabled = false;
    } else {
      selector.append(text('option', 'No verified recording'));
      selector.disabled = true;
    }
    renderLedger();
    renderFrame();
  }

  async function refreshEvidence() {
    if (imported) return;
    try {
      const response = await fetch('./evidence.json', { cache: 'no-store', credentials: 'omit' });
      if (!response.ok) return;
      const value = validateManifest(await response.json());
      // Do not discard a valid in-memory recording because a stale deployment lacks it.
      if (value.runs.length || !manifest.runs.length) useManifest(value);
    } catch { /* Stay explicitly unverified; never substitute a demo fixture. */ }
  }

  function schedule() {
    clearTimeout(timer);
    if (!playing) return;
    timer = setTimeout(() => {
      if (frame < 5) frame += 1;
      if (frame === 5) stop();
      renderFrame();
      if (playing) schedule();
    }, 2400 / speed);
  }

  $('replay-button').addEventListener('click', () => { $('crisis-button').click(); $('drill').scrollIntoView({ behavior: 'smooth', block: 'start' }); });
  $('crisis-button').addEventListener('click', async () => {
    await refreshEvidence();
    if (!currentRun()) {
      $('evidence-dialog').showModal();
      return;
    }
    stop();
    frame = 0;
    started = playing = true;
    renderFrame();
    schedule();
  });
  $('pause-button').addEventListener('click', () => {
    if (playing) stop();
    else { playing = true; schedule(); }
    renderFrame();
  });
  $('reset-button').addEventListener('click', () => { stop(); frame = 0; started = false; renderFrame(); });
  $('speed-button').addEventListener('click', () => {
    speed = speed === 1 ? 2 : 1;
    $('speed-button').textContent = `${speed}× speed`;
    if (playing) schedule();
  });
  timeline.forEach((button, index) => button.addEventListener('click', () => { stop(); frame = index; started = true; renderFrame(); }));
  $('run-select').addEventListener('change', event => { stop(); selected = Number(event.target.value); frame = 0; started = false; renderLedger(); renderFrame(); });

  const tabs = [$('events-tab'), $('policy-tab')];
  function activateTab(index) {
    tabs.forEach((tab, i) => {
      tab.setAttribute('aria-selected', String(i === index));
      tab.tabIndex = i === index ? 0 : -1;
    });
    $('event-panel').hidden = index !== 0;
    $('policy-panel').hidden = index !== 1;
  }
  tabs.forEach((tab, index) => {
    tab.addEventListener('click', () => activateTab(index));
    tab.addEventListener('keydown', event => {
      if (['ArrowRight', 'ArrowLeft', 'Home', 'End'].includes(event.key)) {
        event.preventDefault();
        const next = event.key === 'Home' ? 0 : event.key === 'End' ? 1 : 1 - index;
        activateTab(next);
        tabs[next].focus();
      }
    });
  });
  $('close-dialog').addEventListener('click', () => $('evidence-dialog').close());
  $('evidence-dialog').addEventListener('click', event => {
    if (event.target !== $('evidence-dialog')) return;
    const rect = $('evidence-dialog').getBoundingClientRect();
    if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) $('evidence-dialog').close();
  });
  $('copy-command').addEventListener('click', async () => {
    try { await navigator.clipboard.writeText('./scripts/verify_docker.sh'); notice('Local verification command copied.'); }
    catch { notice('Copy the command from the box and run it in your project Terminal.'); }
  });
  function chooseFile() { $('evidence-dialog').close(); $('evidence-file').click(); }
  $('import-button').addEventListener('click', chooseFile);
  $('dialog-import').addEventListener('click', chooseFile);
  $('evidence-file').addEventListener('change', async event => {
    const file = event.target.files?.[0];
    if (!file) return;
    try {
      assert(file.size <= 1024 * 1024, 'Choose the small sanitized web/evidence.json file, not raw engine logs.');
      const data = validateManifest(JSON.parse(await file.text()));
      assert(data.runs.length > 0, 'This file has no verified containment recording yet.');
      useManifest(data);
      imported = true;
      notice(`${data.runs.length} verified recording(s) loaded locally. Press LAUNCH CRISIS.`);
      $('drill').scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (error) { notice(error instanceof SyntaxError ? 'Choose a valid sanitized JSON recording.' : error.message); }
    event.target.value = '';
  });
  $('download-evidence').addEventListener('click', () => {
    if (!currentRun()) return;
    const blob = new Blob([JSON.stringify(manifest, null, 2) + '\n'], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'escape-room-public-evidence.json';
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  document.addEventListener('visibilitychange', () => { if (document.hidden && playing) { stop(); renderFrame(); } });
  refreshEvidence();
}

if (typeof document !== 'undefined') boot();
