'use strict';

let state = {
  results: null, targetUrl: '', running: false,
  filter: 'all', suiteFilter: 'all', frameworkFilter: 'all', baseline: null
};

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

// Navigation
$$('.nav-item').forEach(btn => {
  btn.addEventListener('click', () => {
    $$('.nav-item').forEach(b => b.classList.remove('active'));
    $$('.view').forEach(v => v.classList.remove('active'));
    btn.classList.add('active');
    $('view-' + btn.dataset.view).classList.add('active');
  });
});

// Auth field visibility
$('auth-type').addEventListener('change', updateAuthFields);

function updateAuthFields() {
  const type = $('auth-type').value;
  const wrap = $('auth-input-wrap');
  const val  = $('auth-value'), hdr = $('auth-header-name');
  const usr  = $('auth-user'),  pwd = $('auth-pass');
  if (type === 'none') { wrap.classList.add('hidden'); return; }
  wrap.classList.remove('hidden');
  [val, hdr, usr, pwd].forEach(f => f.classList.add('hidden'));
  if (type === 'bearer') { val.placeholder = 'Bearer token'; val.classList.remove('hidden'); }
  else if (type === 'apikey') { hdr.classList.remove('hidden'); val.placeholder = 'API key value'; val.classList.remove('hidden'); }
  else if (type === 'cookie') { val.placeholder = 'session=abc123; other=value'; val.classList.remove('hidden'); }
  else if (type === 'basic') { usr.classList.remove('hidden'); pwd.classList.remove('hidden'); }
}

function getAuth() {
  const type = $('auth-type').value;
  if (type === 'none') return null;
  return { type, value: $('auth-value').value.trim(), headerName: $('auth-header-name').value.trim() || 'X-API-Key',
    user: $('auth-user').value.trim(), pass: $('auth-pass').value.trim() };
}

function getOptions() {
  return { sendWafHeader: $('opt-waf-header').checked, useBaseline: $('opt-baseline').checked,
    rotateUA: $('opt-rotate-ua').checked, auth: getAuth() };
}

// Run Tests
runBtn.addEventListener('click', async () => {
  const url = targetInput.value.trim();
  if (!url) { shake(targetInput.closest('.url-input-wrap')); return; }
  if (!/^https?:\/\/.+/.test(url)) {
    targetInput.closest('.url-input-wrap').style.borderColor = 'var(--red)';
    setTimeout(() => targetInput.closest('.url-input-wrap').style.borderColor = '', 2000); return;
  }
  if (!$('permission-check').checked) {
    const row = document.querySelector('.permission-row');
    row.style.background = 'rgba(248,81,73,0.08)'; row.style.borderRadius = '8px'; row.style.padding = '10px';
    setTimeout(() => { row.style.background = ''; row.style.padding = ''; }, 2500);
    showExportStatus('Please confirm you have permission to test this system.', true); return;
  }

  const suites = [];
  if ($('suite-owasp').checked)    suites.push('owasp');
  if ($('suite-ratelimit').checked) suites.push('ratelimit');
  if ($('suite-bot').checked)      suites.push('bot');
  if ($('suite-bypass').checked)   suites.push('bypass');
  if ($('suite-api').checked)      suites.push('api');
  if ($('suite-bizlogic').checked) suites.push('bizlogic');
  if (!suites.length) return;

  const options = getOptions();
  state.running = true; state.targetUrl = url; state.results = null; state.baseline = null;
  runBtn.disabled = true;
  runBtn.classList.add('running');
  runBtn.querySelector('.run-label').textContent = 'Running\u2026';
  const brandStatus = document.querySelector('.brand-status');
  if (brandStatus) brandStatus.innerHTML = '<div class="status-dot"></div>SCANNING';
  progressSect.classList.remove('hidden'); scoreSect.classList.add('hidden');
  liveFeedRows.innerHTML = ''; progressBar.style.width = '0%'; progressBar.style.background = '';

  const suiteNames = { owasp:'OWASP / CWE Core', ratelimit:'Rate Limiting', bot:'Bot Detection',
    bypass:'Bypass Attempts', api:'API Security', bizlogic:'Business Logic' };
  const suiteTotals = { owasp:44, ratelimit:3, bot:10, bypass:15, api:10, bizlogic:8 };
  const suiteOffset = {};
  let cum = 0;
  suites.forEach(s => { suiteOffset[s] = cum; cum += suiteTotals[s] || 0; });
  const grandTotal = cum;

  if (options.useBaseline) {
    progressLabel.textContent = 'Fetching baseline\u2026';
    progressName.textContent = 'Clean GET to establish response baseline';
  }

  const cleanup = window.wafAPI.onProgress(({ suite, current, name }) => {
    const gc = (suiteOffset[suite] || 0) + current;
    progressLabel.textContent = suiteNames[suite] || suite;
    progressCount.textContent = gc + ' / ' + grandTotal;
    progressName.textContent  = name;
    progressBar.style.width   = Math.round((gc / grandTotal) * 100) + '%';
  });

  try {
    const response = await window.wafAPI.runTests({ url, suites, options });
    cleanup();
    if (response.error) { showError(response.error); return; }
    state.results = response.results; state.baseline = response.baseline;
    renderScoreSection(); renderResultsTable();
  } catch (err) { showError(err.message); }
  finally {
    state.running = false; runBtn.disabled = false; runBtn.classList.remove('running');
    runBtn.querySelector('.run-label').textContent = 'Run Tests';
    const brandStatus = document.querySelector('.brand-status');
    if (brandStatus) brandStatus.innerHTML = '<div class="status-dot"></div>READY';
  }
});

// Score Rendering
function renderScoreSection() {
  const suiteLabels = { owasp:'OWASP / CWE Core', ratelimit:'Rate Limiting', bot:'Bot Detection',
    bypass:'Bypass Attempts', api:'API Security', bizlogic:'Business Logic' };
  let totalBlocked = 0, totalTests = 0;
  scoreCards.innerHTML = '';

  for (const [suite, tests] of Object.entries(state.results)) {
    const blocked = tests.filter(t => t.blocked === true).length;
    const total   = tests.length;
    const score   = total > 0 ? Math.round((blocked / total) * 100) : 0;
    totalBlocked += blocked; totalTests += total;

    // SVG ring parameters
    const r = 30, circ = 2 * Math.PI * r;
    const offset = circ - (score / 100) * circ;
    const ringColor = score >= 80 ? 'var(--green)' : score >= 50 ? 'var(--yellow)' : 'var(--red)';

    const card = document.createElement('div');
    card.className = 'score-card';
    card.innerHTML =
      '<div class="score-ring-wrap">' +
        '<svg width="72" height="72" viewBox="0 0 72 72">' +
          '<circle class="score-ring-bg" cx="36" cy="36" r="' + r + '"/>' +
          '<circle class="score-ring-fill" cx="36" cy="36" r="' + r + '" ' +
            'stroke="' + ringColor + '" ' +
            'stroke-dasharray="' + circ.toFixed(1) + '" ' +
            'stroke-dashoffset="' + circ.toFixed(1) + '" ' +
            'style="transition:stroke-dashoffset 1s ease;"/>' +
        '</svg>' +
        '<div class="score-ring-text" style="color:' + ringColor + '">' + score + '%</div>' +
      '</div>' +
      '<div class="score-card-label">' + (suiteLabels[suite]||suite) + '</div>' +
      '<div class="score-card-detail">' + blocked + ' / ' + total + '</div>';
    scoreCards.appendChild(card);

    // Animate ring after paint
    requestAnimationFrame(() => {
      setTimeout(() => {
        const ring = card.querySelector('.score-ring-fill');
        if (ring) ring.style.strokeDashoffset = offset.toFixed(1);
      }, 50);
    });
  }

  const overall    = totalTests > 0 ? Math.round((totalBlocked / totalTests) * 100) : 0;
  const color      = overall >= 80 ? 'var(--green)' : overall >= 50 ? 'var(--yellow)' : 'var(--red)';
  const grade      = overall >= 90 ? 'A' : overall >= 80 ? 'B' : overall >= 65 ? 'C' : overall >= 50 ? 'D' : 'F';
  const gradeBg    = overall >= 80 ? 'rgba(0,230,118,0.08)' : overall >= 50 ? 'rgba(255,193,7,0.08)' : 'rgba(255,61,87,0.08)';
  const gradeBorder= overall >= 80 ? 'rgba(0,230,118,0.3)' : overall >= 50 ? 'rgba(255,193,7,0.3)' : 'rgba(255,61,87,0.3)';

  overallScore.textContent = overall + '%';
  overallScore.style.color = color;
  overallGrade.textContent = grade;
  overallGrade.style.color = color;
  overallGrade.style.background = gradeBg;
  overallGrade.style.borderColor = gradeBorder;

  const old = document.querySelector('.baseline-indicator');
  if (old) old.remove();
  if (state.baseline) {
    const ind = document.createElement('div');
    ind.className = 'baseline-indicator';
    ind.textContent = 'Baseline: HTTP ' + state.baseline.status + ' \u00B7 ' + state.baseline.latency + 'ms \u2014 confidence scoring active';
    scoreSect.querySelector('.score-header').after(ind);
  }

  scoreSect.classList.remove('hidden');
  liveFeedRows.innerHTML = '';
  for (const tests of Object.values(state.results)) for (const t of tests) addFeedRow(t.name, t.blocked, t.confidence);
}

function addFeedRow(name, blocked, confidence) {
  const cls   = blocked === true ? 'blocked' : blocked === false ? 'passed' : 'error';
  const label = blocked === true ? 'BLOCKED' : blocked === false ? 'BYPASSED' : 'ERROR';
  const badge = (blocked === true && confidence)
    ? '<span class="conf-badge ' + confidence + '">' + confidence.toUpperCase() + '</span>' : '';
  const row = document.createElement('div');
  row.className = 'feed-row';
  row.innerHTML = '<span class="feed-dot ' + cls + '"></span><span class="feed-name">' + esc(name) + '</span>'
    + badge + '<span class="feed-status ' + cls + '">' + label + '</span>';
  liveFeedRows.appendChild(row);
  liveFeedRows.scrollTop = liveFeedRows.scrollHeight;
}

// Compliance tag colors
const tagColors = {
  'OWASP': '#f0883e', 'CWE': '#79c0ff', 'NIST': '#7ee787', 'PCI': '#d2a8ff'
};
function renderTagBadges(tags) {
  if (!tags || !tags.length) return '';
  return tags.map(tag => {
    const prefix = tag.split(':')[0];
    const color = tagColors[prefix] || '#8b949e';
    return '<span class="tag-badge" style="border-color:' + color + ';color:' + color + '">' + tag + '</span>';
  }).join('');
}

// Results Table
function renderResultsTable() {
  if (!state.results) { resultsTbl.innerHTML = '<div class="empty-state">Run tests to see detailed results</div>'; return; }
  const suiteLabels = { owasp:'OWASP / CWE Core', ratelimit:'Rate Limiting', bot:'Bot Detection',
    bypass:'Bypass Attempts', api:'API Security', bizlogic:'Business Logic' };
  let allTests = [];
  for (const [suite, tests] of Object.entries(state.results)) tests.forEach(t => allTests.push(Object.assign({}, t, { suite })));

  let filtered = allTests;
  if (state.filter === 'blocked') filtered = filtered.filter(t => t.blocked === true);
  if (state.filter === 'passed')  filtered = filtered.filter(t => t.blocked === false);
  if (state.filter === 'error')   filtered = filtered.filter(t => t.blocked === null);
  if (state.suiteFilter !== 'all') filtered = filtered.filter(t => t.suite === state.suiteFilter);
  if (state.frameworkFilter !== 'all') filtered = filtered.filter(t => (t.tags||[]).some(tag => tag.startsWith(state.frameworkFilter)));

  if (!filtered.length) { resultsTbl.innerHTML = '<div class="empty-state">No results match the current filter</div>'; return; }

  const confBadge = { high:'HIGH', likely:'LIKELY', uncertain:'UNCERTAIN' };
  const rows = filtered.map(t => {
    const cls      = t.blocked === true ? 'blocked' : t.blocked === false ? 'bypassed' : 'error';
    const rowCls   = t.blocked === true ? 'row-blocked' : t.blocked === false ? 'row-bypassed' : '';
    const label    = t.blocked === true ? '\u2713 BLOCKED' : t.blocked === false ? '\u2717 BYPASSED' : '? ERROR';
    const badge    = (t.blocked === true && confBadge[t.confidence]) ? '<span class="conf-badge ' + t.confidence + '">' + confBadge[t.confidence] + '</span>' : '';
    const statusColor = !t.status ? 'var(--muted)' : t.status >= 400 ? 'var(--green)' : 'var(--muted)';
    return '<tr class="' + rowCls + '">'
      + '<td><div class="td-name">' + esc(t.name) + '</div><div class="td-category">' + esc(suiteLabels[t.suite]||t.suite) + '</div></td>'
      + '<td class="td-payload" title="' + esc(t.payload) + '">' + esc(t.payload) + '</td>'
      + '<td>' + renderTagBadges(t.tags) + '</td>'
      + '<td class="td-status" style="color:' + statusColor + '">' + (t.status||'\u2013') + '</td>'
      + '<td class="td-latency">' + t.latency + 'ms</td>'
      + '<td class="td-result ' + cls + '">' + label + ' ' + badge + '</td>'
      + '<td class="td-reason">' + esc(t.reason) + '</td>'
      + '</tr>';
  }).join('');

  resultsTbl.innerHTML = '<table class="results-table"><thead><tr>'
    + '<th>Test</th><th>Payload</th><th>Frameworks</th><th>Status</th><th>Latency</th><th>Result</th><th>Reason</th>'
    + '</tr></thead><tbody>' + rows + '</tbody></table>';
}

// Filters
$$('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    $$('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active'); state.filter = btn.dataset.filter; renderResultsTable();
  });
});
$('suite-filter').addEventListener('change', e => { state.suiteFilter = e.target.value; renderResultsTable(); });
$('framework-filter').addEventListener('change', e => { state.frameworkFilter = e.target.value; renderResultsTable(); });

// Export
async function doExportJson() {
  if (!state.results) { showExportStatus('No results yet \u2014 run tests first.', true); return; }
  try {
    const res = await window.wafAPI.exportReport({ results: state.results, url: state.targetUrl });
    if (res.cancelled) return;
    if (res.saved) showExportStatus('\u2713 JSON saved: ' + res.path);
    else showExportStatus('Export failed.', true);
  } catch (err) { showExportStatus('Export error: ' + err.message, true); }
}
async function doExportHtml() {
  if (!state.results) { showExportStatus('No results yet \u2014 run tests first.', true); return; }
  try {
    const res = await window.wafAPI.exportHtmlReport({ results: state.results, url: state.targetUrl });
    if (res.cancelled) return;
    if (res.saved) showExportStatus('\u2713 HTML report saved and opened');
    else showExportStatus('Export failed.', true);
  } catch (err) { showExportStatus('Export error: ' + err.message, true); }
}
$('export-json-btn').addEventListener('click', doExportJson);
$('export-html-btn').addEventListener('click', doExportHtml);
$('export-json-btn2').addEventListener('click', doExportJson);
$('export-html-btn2').addEventListener('click', doExportHtml);

function showExportStatus(msg, isError) {
  const el = $('export-status');
  el.textContent = msg;
  el.style.background  = isError ? 'rgba(248,81,73,0.15)' : 'rgba(63,185,80,0.15)';
  el.style.borderColor = isError ? 'rgba(248,81,73,0.4)'  : 'rgba(63,185,80,0.4)';
  el.style.color = isError ? 'var(--red)' : 'var(--green)';
  el.classList.remove('hidden'); clearTimeout(el._timer);
  el._timer = setTimeout(() => el.classList.add('hidden'), 5000);
  const page = $('export-status-page');
  if (page) {
    page.textContent = msg; page.className = 'export-status' + (isError ? ' error' : '');
    page.classList.remove('hidden'); clearTimeout(page._timer);
    page._timer = setTimeout(() => page.classList.add('hidden'), 5000);
  }
}

function esc(str) { return String(str||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function shake(el) { el.style.borderColor='var(--red)'; setTimeout(()=>el.style.borderColor='',2000); }
function showError(msg) {
  progressLabel.textContent='Error'; progressName.textContent=msg;
  progressBar.style.width='100%'; progressBar.style.background='var(--red)';
}
