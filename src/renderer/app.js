'use strict';

// ── State ──────────────────────────────────────
let state = {
  results: null,
  targetUrl: '',
  running: false,
  filter: 'all',
  suiteFilter: 'all',
  baseline: null
};

// ── DOM refs ───────────────────────────────────
const $ = id => document.getElementById(id);
const $$ = sel => document.querySelectorAll(sel);

const runBtn        = $('run-btn');
const targetInput   = $('target-url');
const progressSect  = $('progress-section');
const scoreSect     = $('score-section');
const scoreCards    = $('score-cards');
const progressBar   = $('progress-bar');
const progressLabel = $('progress-suite-label');
const progressCount = $('progress-counter');
const progressName  = $('progress-test-name');
const liveFeedRows  = $('live-feed-rows');
const overallScore  = $('overall-score');
const overallGrade  = $('overall-grade');
const resultsTbl    = $('results-table-wrap');

// ── Navigation ─────────────────────────────────
$$('.nav-item').forEach(btn => {
  btn.addEventListener('click', () => {
    $$('.nav-item').forEach(b => b.classList.remove('active'));
    $$('.view').forEach(v => v.classList.remove('active'));
    btn.classList.add('active');
    $('view-' + btn.dataset.view).classList.add('active');
  });
});

// ── Auth field visibility ──────────────────────
$('auth-type').addEventListener('change', updateAuthFields);

function updateAuthFields() {
  const type      = $('auth-type').value;
  const wrap      = $('auth-input-wrap');
  const valField  = $('auth-value');
  const hdrField  = $('auth-header-name');
  const userField = $('auth-user');
  const passField = $('auth-pass');

  if (type === 'none') { wrap.classList.add('hidden'); return; }
  wrap.classList.remove('hidden');
  [valField, hdrField, userField, passField].forEach(f => f.classList.add('hidden'));

  if (type === 'bearer') {
    valField.placeholder = 'Bearer token';
    valField.classList.remove('hidden');
  } else if (type === 'apikey') {
    hdrField.classList.remove('hidden');
    valField.placeholder = 'API key value';
    valField.classList.remove('hidden');
  } else if (type === 'cookie') {
    valField.placeholder = 'session=abc123; other=value';
    valField.classList.remove('hidden');
  } else if (type === 'basic') {
    userField.classList.remove('hidden');
    passField.classList.remove('hidden');
  }
}

function getAuth() {
  const type = $('auth-type').value;
  if (type === 'none') return null;
  return {
    type,
    value:      $('auth-value').value.trim(),
    headerName: $('auth-header-name').value.trim() || 'X-API-Key',
    user:       $('auth-user').value.trim(),
    pass:       $('auth-pass').value.trim()
  };
}

function getOptions() {
  return {
    sendWafHeader: $('opt-waf-header').checked,
    useBaseline:   $('opt-baseline').checked,
    rotateUA:      $('opt-rotate-ua').checked,
    auth:          getAuth()
  };
}

// ── Run Tests ──────────────────────────────────
runBtn.addEventListener('click', async () => {
  const url = targetInput.value.trim();
  if (!url) { shake(targetInput.closest('.url-input-wrap')); return; }
  if (!/^https?:\/\/.+/.test(url)) {
    targetInput.closest('.url-input-wrap').style.borderColor = 'var(--red)';
    setTimeout(() => targetInput.closest('.url-input-wrap').style.borderColor = '', 2000);
    return;
  }

  if (!$('permission-check').checked) {
    const row = document.querySelector('.permission-row');
    row.style.background   = 'rgba(248,81,73,0.08)';
    row.style.borderRadius = '8px';
    row.style.padding      = '10px';
    setTimeout(() => { row.style.background = ''; row.style.padding = ''; }, 2500);
    showExportStatus('Please confirm you have permission to test this system.', true);
    return;
  }

  const suites = [];
  if ($('suite-owasp').checked)     suites.push('owasp');
  if ($('suite-ratelimit').checked) suites.push('ratelimit');
  if ($('suite-bot').checked)       suites.push('bot');
  if ($('suite-bypass').checked)    suites.push('bypass');
  if (!suites.length) return;

  const options = getOptions();

  state.running   = true;
  state.targetUrl = url;
  state.results   = null;
  state.baseline  = null;

  runBtn.disabled = true;
  runBtn.querySelector('.run-label').textContent = 'Running\u2026';
  progressSect.classList.remove('hidden');
  scoreSect.classList.add('hidden');
  liveFeedRows.innerHTML    = '';
  progressBar.style.width   = '0%';
  progressBar.style.background = '';

  const suiteNames  = { owasp: 'OWASP Top 10', ratelimit: 'Rate Limiting', bot: 'Bot Detection', bypass: 'Bypass Attempts' };
  const suiteTotals = { owasp: 15, ratelimit: 3, bot: 10, bypass: 12 };
  const suiteOffset = {};
  let cumulativeTotal = 0;
  suites.forEach(s => { suiteOffset[s] = cumulativeTotal; cumulativeTotal += suiteTotals[s] || 0; });
  const grandTotal = cumulativeTotal;

  if (options.useBaseline) {
    progressLabel.textContent = 'Fetching baseline\u2026';
    progressName.textContent  = 'Clean GET to establish response baseline';
  }

  const cleanup = window.wafAPI.onProgress(({ suite, current, name }) => {
    const globalCurrent = (suiteOffset[suite] || 0) + current;
    const pct = Math.round((globalCurrent / grandTotal) * 100);
    progressLabel.textContent = suiteNames[suite] || suite;
    progressCount.textContent = globalCurrent + ' / ' + grandTotal;
    progressName.textContent  = name;
    progressBar.style.width   = pct + '%';
  });

  try {
    const response = await window.wafAPI.runTests({ url, suites, options });
    cleanup();
    if (response.error) { showError(response.error); return; }
    state.results  = response.results;
    state.baseline = response.baseline;
    renderScoreSection();
    renderResultsTable();
  } catch (err) {
    showError(err.message);
  } finally {
    state.running = false;
    runBtn.disabled = false;
    runBtn.querySelector('.run-label').textContent = 'Run Tests';
  }
});

// ── Score Rendering ────────────────────────────
function renderScoreSection() {
  const suiteLabels = { owasp: 'OWASP Top 10', ratelimit: 'Rate Limiting', bot: 'Bot Detection', bypass: 'Bypass Attempts' };
  let totalBlocked = 0, totalTests = 0;
  scoreCards.innerHTML = '';

  for (const [suite, tests] of Object.entries(state.results)) {
    const blocked = tests.filter(t => t.blocked === true).length;
    const total   = tests.length;
    const score   = total > 0 ? Math.round((blocked / total) * 100) : 0;
    totalBlocked += blocked;
    totalTests   += total;
    const color = score >= 80 ? 'var(--green)' : score >= 50 ? 'var(--yellow)' : 'var(--red)';
    const card  = document.createElement('div');
    card.className = 'score-card';
    card.innerHTML = '<div class="score-card-label">' + (suiteLabels[suite] || suite) + '</div>'
      + '<div class="score-card-value" style="color:' + color + '">' + score + '%</div>'
      + '<div class="score-card-detail">' + blocked + ' / ' + total + ' blocked</div>';
    scoreCards.appendChild(card);
  }

  const overall    = totalTests > 0 ? Math.round((totalBlocked / totalTests) * 100) : 0;
  const color      = overall >= 80 ? 'var(--green)' : overall >= 50 ? 'var(--yellow)' : 'var(--red)';
  const grade      = overall >= 90 ? 'A' : overall >= 80 ? 'B' : overall >= 65 ? 'C' : overall >= 50 ? 'D' : 'F';
  const gradeColor = overall >= 80 ? 'rgba(63,185,80,0.15)' : overall >= 50 ? 'rgba(210,153,34,0.15)' : 'rgba(248,81,73,0.15)';

  overallScore.textContent      = overall + '%';
  overallScore.style.color      = color;
  overallGrade.textContent      = grade;
  overallGrade.style.color      = color;
  overallGrade.style.background = gradeColor;

  const old = document.querySelector('.baseline-indicator');
  if (old) old.remove();
  if (state.baseline) {
    const ind = document.createElement('div');
    ind.className = 'baseline-indicator';
    ind.textContent = '\u2B21 Baseline: HTTP ' + state.baseline.status + ' \u00B7 ' + state.baseline.latency + 'ms \u2014 confidence scoring active';
    scoreSect.querySelector('.score-header').after(ind);
  }

  scoreSect.classList.remove('hidden');
  liveFeedRows.innerHTML = '';
  for (const tests of Object.values(state.results)) {
    for (const t of tests) addFeedRow(t.name, t.blocked, t.confidence);
  }
}

function addFeedRow(name, blocked, confidence) {
  const cls   = blocked === true ? 'blocked' : blocked === false ? 'passed' : 'error';
  const label = blocked === true ? 'BLOCKED' : blocked === false ? 'BYPASSED' : 'ERROR';
  const badge = (blocked === true && confidence)
    ? '<span class="conf-badge ' + confidence + '">' + confidence.toUpperCase() + '</span>' : '';
  const row = document.createElement('div');
  row.className = 'feed-row';
  row.innerHTML = '<span class="feed-dot ' + cls + '"></span>'
    + '<span class="feed-name">' + esc(name) + '</span>'
    + badge
    + '<span class="feed-status ' + cls + '">' + label + '</span>';
  liveFeedRows.appendChild(row);
  liveFeedRows.scrollTop = liveFeedRows.scrollHeight;
}

// ── Results Table ──────────────────────────────
function renderResultsTable() {
  if (!state.results) {
    resultsTbl.innerHTML = '<div class="empty-state">Run tests to see detailed results</div>';
    return;
  }

  const suiteLabels = { owasp: 'OWASP Top 10', ratelimit: 'Rate Limiting', bot: 'Bot Detection', bypass: 'Bypass Attempts' };
  let allTests = [];
  for (const [suite, tests] of Object.entries(state.results)) {
    tests.forEach(t => allTests.push(Object.assign({}, t, { suite })));
  }

  let filtered = allTests;
  if (state.filter === 'blocked') filtered = filtered.filter(t => t.blocked === true);
  if (state.filter === 'passed')  filtered = filtered.filter(t => t.blocked === false);
  if (state.filter === 'error')   filtered = filtered.filter(t => t.blocked === null);
  if (state.suiteFilter !== 'all') filtered = filtered.filter(t => t.suite === state.suiteFilter);

  if (!filtered.length) {
    resultsTbl.innerHTML = '<div class="empty-state">No results match the current filter</div>';
    return;
  }

  const confBadge = { high: 'HIGH', likely: 'LIKELY', uncertain: 'UNCERTAIN' };

  const rows = filtered.map(t => {
    const cls   = t.blocked === true ? 'blocked' : t.blocked === false ? 'bypassed' : 'error';
    const label = t.blocked === true ? '\u2713 BLOCKED' : t.blocked === false ? '\u2717 BYPASSED' : '? ERROR';
    const badge = (t.blocked === true && confBadge[t.confidence])
      ? '<span class="conf-badge ' + t.confidence + '">' + confBadge[t.confidence] + '</span>' : '';
    const statusColor = !t.status ? 'var(--muted)' : t.status >= 400 ? 'var(--green)' : 'var(--muted)';
    return '<tr>'
      + '<td><div class="td-name">' + esc(t.name) + '</div><div class="td-category">' + esc(suiteLabels[t.suite] || t.suite) + '</div></td>'
      + '<td class="td-payload" title="' + esc(t.payload) + '">' + esc(t.payload) + '</td>'
      + '<td class="td-status" style="color:' + statusColor + '">' + (t.status || '\u2013') + '</td>'
      + '<td class="td-latency">' + t.latency + 'ms</td>'
      + '<td class="td-result ' + cls + '">' + label + ' ' + badge + '</td>'
      + '<td class="td-reason">' + esc(t.reason) + '</td>'
      + '</tr>';
  }).join('');

  resultsTbl.innerHTML = '<table class="results-table"><thead><tr>'
    + '<th>Test</th><th>Payload</th><th>Status</th><th>Latency</th><th>Result</th><th>Reason</th>'
    + '</tr></thead><tbody>' + rows + '</tbody></table>';
}

// ── Filters ────────────────────────────────────
$$('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    $$('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    state.filter = btn.dataset.filter;
    renderResultsTable();
  });
});

$('suite-filter').addEventListener('change', e => {
  state.suiteFilter = e.target.value;
  renderResultsTable();
});

// ── Export ─────────────────────────────────────
async function doExportJson() {
  if (!state.results) { showExportStatus('No results yet \u2014 run tests first.', true); return; }
  try {
    const res = await window.wafAPI.exportReport({ results: state.results, url: state.targetUrl });
    if (res.cancelled) return;
    if (res.saved) showExportStatus('\u2713 JSON saved: ' + res.path);
    else showExportStatus('Export failed \u2014 unknown error.', true);
  } catch (err) { showExportStatus('Export error: ' + err.message, true); }
}

async function doExportHtml() {
  if (!state.results) { showExportStatus('No results yet \u2014 run tests first.', true); return; }
  try {
    const res = await window.wafAPI.exportHtmlReport({ results: state.results, url: state.targetUrl });
    if (res.cancelled) return;
    if (res.saved) showExportStatus('\u2713 HTML report saved and opened');
    else showExportStatus('Export failed \u2014 unknown error.', true);
  } catch (err) { showExportStatus('Export error: ' + err.message, true); }
}

$('export-json-btn').addEventListener('click', doExportJson);
$('export-html-btn').addEventListener('click', doExportHtml);
$('export-json-btn2').addEventListener('click', doExportJson);
$('export-html-btn2').addEventListener('click', doExportHtml);

function showExportStatus(msg, isError) {
  const el = $('export-status');
  el.textContent       = msg;
  el.style.background  = isError ? 'rgba(248,81,73,0.15)' : 'rgba(63,185,80,0.15)';
  el.style.borderColor = isError ? 'rgba(248,81,73,0.4)'  : 'rgba(63,185,80,0.4)';
  el.style.color       = isError ? 'var(--red)' : 'var(--green)';
  el.classList.remove('hidden');
  clearTimeout(el._timer);
  el._timer = setTimeout(() => el.classList.add('hidden'), 5000);

  const page = $('export-status-page');
  if (page) {
    page.textContent = msg;
    page.className   = 'export-status' + (isError ? ' error' : '');
    page.classList.remove('hidden');
    clearTimeout(page._timer);
    page._timer = setTimeout(() => page.classList.add('hidden'), 5000);
  }
}

// ── Helpers ────────────────────────────────────
function esc(str) {
  return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function shake(el) {
  el.style.borderColor = 'var(--red)';
  setTimeout(() => el.style.borderColor = '', 2000);
}

function showError(msg) {
  progressLabel.textContent    = 'Error';
  progressName.textContent     = msg;
  progressBar.style.width      = '100%';
  progressBar.style.background = 'var(--red)';
}
