// Incident Commander: replays recorded local Docker runs of engine/commander.py.
// Every value shown comes from web/commander.json; nothing here executes or invents outcomes.
export const SCENARIOS = {
  standard: ['STANDARD BREACH', 'Drift in the active config'],
  persistent: ['FAILED VERIFICATION', 'A hidden layer re-applies drift'],
  escalation: ['OUT OF AUTHORITY', 'Drift source the agent does not own'],
  recurrence: ['REPEATED DRIFT', 'The same incident tries again'],
};
export const LOOP = ['DETECT', 'INVESTIGATE', 'DECIDE', 'CONTAIN', 'VERIFY', 'PREVENT', 'REPORT'];
const OUTCOMES = { VERIFIED_SAFE: 'VERIFIED SAFE', ESCALATED: 'RECOVERY FAILED — ESCALATED', RECURRENCE_BLOCKED: 'RECURRENCE BLOCKED' };
const STATUS = new Set(['PASS', 'FAIL', 'INCONCLUSIVE']);
const PREVENTION = new Set(['APPLIED', 'RECOMMENDED', 'BLOCKED', 'UNVERIFIED', 'FAILED']);
const str = (v, max = 400) => typeof v === 'string' && v.length <= max ? v : '';
const strs = (v, max) => Array.isArray(v) ? v.slice(0, 20).map(x => str(x, max)).filter(Boolean) : [];
const ok = (c, m) => { if (!c) throw new Error(m); };

export function validateCommander(input) {
  ok(input && input.schema_version === 1 && Array.isArray(input.scenarios), 'Invalid commander record.');
  const scenarios = input.scenarios.map(r => {
    ok(SCENARIOS[r.scenario] && OUTCOMES[r.outcome] && STATUS.has(r.status), 'Unknown scenario or outcome.');
    ok(/^[a-f0-9]{32}$/.test(r.run_id) && /^[a-f0-9]{64}$/.test(r.source_sha256) && /^[a-f0-9]{16}$/.test(r.fingerprint), 'Provenance missing.');
    ok(r.cleanup_complete === true, 'Cleanup not verified.');
    ok(Array.isArray(r.attempts) && Number.isInteger(r.max_attempts) && r.attempts.length <= r.max_attempts, 'Attempt bound violated.');
    const safe = r.final_probes?.network === 'PASS' && r.final_probes?.secret === 'PASS';
    ok(r.outcome === 'ESCALATED' ? r.status === 'FAIL' && !safe : r.status === 'PASS' && safe, 'Outcome contradicts final probes.');
    const decisions = r.decisions.map(d => ({
      attempt: d.attempt, facts: strs(d.facts), severity: str(d.severity, 20), classification: str(d.classification, 40),
      evidence_confidence: str(d.evidence_confidence, 20), boundaries_violated: strs(d.boundaries_violated, 40),
      root_cause: str(d.root_cause, 60), root_cause_evidence: str(d.root_cause_evidence), selected_action: str(d.selected_action, 60),
      outcome: str(d.outcome, 20), rationale: str(d.rationale), verification_criteria: strs(d.verification_criteria),
      candidates: (d.candidates || []).map(c => ({ action: str(c.action, 60), allowed: c.allowed === true, reason: str(c.reason) }))
    }));
    return { scenario: r.scenario, outcome: r.outcome, status: r.status, run_id: r.run_id, source_sha256: r.source_sha256,
      recorded_at: str(r.recorded_at, 40), fingerprint: r.fingerprint, event_count: r.event_count | 0,
      prior_matches: (r.prior_matches || []).map(p => ({ run_id: str(p.run_id, 32), recorded_at: str(p.recorded_at, 40) })),
      root_cause_chain: strs(r.root_cause_chain, 60), attempts: r.attempts.map(a => str(a.action, 60)), max_attempts: r.max_attempts,
      final_probes: { network: r.final_probes.network, secret: r.final_probes.secret }, decisions,
      prevention: r.prevention.filter(p => PREVENTION.has(p.status)).map(p => ({ status: p.status, action: str(p.action, 80), detail: str(p.detail), verified: str(p.verified) })),
      recurrence: r.recurrence ? { blocked_by_guard: r.recurrence.blocked_by_guard === true, still_contained: r.recurrence.still_contained === true } : null,
      regression_rule: str(r.regression_rule, 4000), regression_status: STATUS.has(r.regression_status) ? r.regression_status : 'INCONCLUSIVE',
      timeline: r.timeline.filter(t => LOOP.includes(t.step) && STATUS.has(t.status)).map(t => ({ step: t.step, label: str(t.label, 120), status: t.status, t: str(t.t, 40) })) };
  });
  return { scenarios };
}

function boot() {
  const $ = id => document.getElementById(id);
  const root = $('commander');
  if (!root) return;
  const el = (tag, cls, txt) => { const e = document.createElement(tag); if (cls) e.className = cls; if (txt != null) e.textContent = txt; return e; };
  let data = null, current = null, timer = null, decisionIndex = 0;

  function renderDecision(run) {
    const d = run.decisions[decisionIndex];
    const tabs = $('cmd-decision-tabs');
    tabs.replaceChildren(...run.decisions.map((x, i) => {
      const b = el('button', i === decisionIndex ? 'active' : '', `#${x.attempt} ${x.outcome.replace('_', ' ')}`);
      b.addEventListener('click', () => { decisionIndex = i; renderDecision(run); });
      return b;
    }));
    const body = $('cmd-decision');
    body.replaceChildren();
    const grid = el('div', 'cmd-kv');
    [['SEVERITY', d.severity], ['CLASSIFICATION', d.classification.replaceAll('_', ' ')], ['CONFIDENCE', d.evidence_confidence],
     ['BOUNDARIES', d.boundaries_violated.join(' + ') || 'none violated']].forEach(([k, v]) => {
      const cell = el('div'); cell.append(el('span', '', k), el('strong', '', v)); grid.append(cell);
    });
    body.append(grid);
    const facts = el('ul', 'cmd-facts');
    d.facts.forEach(f => facts.append(el('li', /ACCESS OBSERVED/.test(f) ? 'bad' : '', f)));
    body.append(el('h4', '', 'Observed facts'), facts);
    if (d.root_cause) body.append(el('h4', '', 'Root cause · ' + d.root_cause.replaceAll('_', ' ')), el('p', 'cmd-cause', d.root_cause_evidence));
    if (d.candidates.length) {
      const list = el('ul', 'cmd-candidates');
      d.candidates.forEach(c => {
        const li = el('li', (c.allowed ? 'allowed' : 'rejected') + (c.action === d.selected_action ? ' chosen' : ''));
        li.append(el('code', '', c.action), el('span', '', (c.action === d.selected_action ? 'SELECTED · ' : c.allowed ? '' : 'REJECTED · ') + c.reason));
        list.append(li);
      });
      body.append(el('h4', '', 'Candidate actions'), list);
    }
    body.append(el('p', 'cmd-rationale', d.rationale));
  }

  function render(name, animate) {
    clearTimeout(timer);
    const run = data.scenarios.find(r => r.scenario === name);
    if (!run) return;
    current = name;
    root.dataset.outcome = run.outcome;
    root.querySelectorAll('.cmd-scenarios button').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.scenario === name)));
    $('cmd-outcome').textContent = OUTCOMES[run.outcome];
    $('cmd-outcome-sub').textContent = `${run.attempts.length} of ${run.max_attempts} remediation attempts · final probes: network ${run.final_probes.network}, canary ${run.final_probes.secret}`;
    // Open the decisive call: the last decision that weighed candidate actions.
    decisionIndex = run.decisions.reduce((last, d, i) => d.candidates.length ? i : last, 0);
    renderDecision(run);
    const list = $('cmd-timeline');
    list.replaceChildren();
    const items = run.timeline.map(t => {
      const li = el('li', 'step-' + t.status.toLowerCase());
      li.append(el('span', 'cmd-step', t.step), el('span', '', t.label), el('time', '', new Date(t.t).toLocaleTimeString([], { hour12: false })));
      if (animate) li.classList.add('pending');
      list.append(li);
      return li;
    });
    const loop = $('cmd-loop');
    loop.replaceChildren(...LOOP.map(s => el('span', run.timeline.some(t => t.step === s) ? 'done' : 'skipped', s)));
    if (animate) {
      let i = 0;
      const reveal = () => { if (i < items.length) { items[i++].classList.remove('pending'); timer = setTimeout(reveal, 420); } };
      reveal();
    }
    const prev = $('cmd-prevention');
    prev.replaceChildren(...run.prevention.map(p => {
      const li = el('li');
      li.append(el('span', 'chip ' + p.status.toLowerCase(), p.status), el('strong', '', p.action), el('span', '', p.detail), el('small', '', p.verified));
      return li;
    }));
    $('cmd-fingerprint').textContent = run.fingerprint;
    $('cmd-recurrence').textContent = run.prior_matches.length
      ? `Seen before: matches ${run.prior_matches.length} earlier recorded incident(s) (${run.prior_matches.map(p => p.run_id.slice(0, 8)).join(', ')})`
      : 'First occurrence of this fingerprint in the local evidence store';
    $('cmd-provenance').textContent = `Recorded local Docker run ${run.run_id.slice(0, 8)} · ${run.event_count} events · source sha256 ${run.source_sha256.slice(0, 12)}… · cleanup verified · reproduce: python -m engine.commander ${run.scenario}`;
  }

  root.querySelector('.cmd-scenarios').replaceChildren(...Object.entries(SCENARIOS).map(([key, [title, sub]]) => {
    const b = el('button');
    b.dataset.scenario = key;
    b.disabled = true;
    b.append(el('strong', '', title), el('span', '', sub));
    b.addEventListener('click', () => render(key, true));
    return b;
  }));
  $('cmd-download').addEventListener('click', () => {
    const run = data?.scenarios.find(r => r.scenario === current);
    if (!run?.regression_rule) return;
    const url = URL.createObjectURL(new Blob([run.regression_rule], { type: 'text/yaml' }));
    const a = el('a'); a.href = url; a.download = `escape-room-regression-${run.fingerprint}.yaml`; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  fetch('./commander.json', { cache: 'no-store', credentials: 'omit' }).then(r => r.ok ? r.json() : Promise.reject())
    .then(json => {
      data = validateCommander(json);
      root.querySelectorAll('.cmd-scenarios button').forEach(b => { b.disabled = !data.scenarios.some(r => r.scenario === b.dataset.scenario); });
      if (data.scenarios.length) render(data.scenarios[0].scenario, false);
    }).catch(() => { $('cmd-outcome').textContent = 'NO VERIFIED COMMANDER RECORDING'; });
}

if (typeof document !== 'undefined') boot();
