# 🛡️ WAF Tester

**Enterprise WAF Evaluation Tool** — Real attack payloads. Real results. Compliance-ready reports.

WAF Tester evaluates Web Application Firewalls by sending real attack payloads to a user-supplied URL and reporting whether they are blocked. Available as a Windows desktop app (Electron) and a Python CLI that runs anywhere.

---

## ⚠️ Legal Disclaimer

**This tool is intended for authorized security testing only.**
Only use it against systems you own or have explicit written permission to test.
Unauthorized testing of third-party systems may violate the Computer Fraud and Abuse Act (CFAA) and equivalent laws in your jurisdiction.
The authors assume no liability for misuse.

---

## Features

### Test Coverage — 90 Tests Across 6 Suites

| Suite | Tests | What It Covers |
|-------|------:|----------------|
| **OWASP / CWE Core** | 44 | SQL injection (12 variants), XSS (10 variants), path traversal, command injection, XXE, SSRF, Log4Shell, SSTI, open redirect |
| **Rate Limiting** | 3 | Burst flood (30 concurrent), sequential flood, X-Forwarded-For IP rotation bypass |
| **Bot Detection** | 10 | sqlmap, Nikto, Nmap, Scrapy, Masscan, HeadlessChrome, python-requests, curl, empty UA, missing Accept headers |
| **Bypass Attempts** | 15 | Double URL-encoding, Unicode fullwidth, null bytes, case variation, comment obfuscation, CRLF injection, host header injection, method override, path tricks |
| **API Security** | 10 | GraphQL introspection/batch/enumeration, JWT none-algorithm & algorithm confusion, mass assignment, HTTP verb tampering, BOLA, content-type confusion |
| **Business Logic** | 8 | Negative quantity, zero-price submission, admin endpoint access, HTTP parameter pollution, account enumeration, excessive data exposure, forced browsing, privilege escalation |

### Compliance Mapping

Every test is tagged to one or more compliance frameworks:

- **OWASP Top 10 2021** (A01–A10)
- **CWE** (Common Weakness Enumeration)
- **NIST 800-53** (SI-10, AC-3, SC-5, IA-5, etc.)
- **PCI-DSS 4.0** (Requirement 6.4)

### Detection Intelligence

- **Baseline comparison** — fetches a clean GET before tests run, then compares every response to reduce false positives
- **Confidence scoring** — results rated `HIGH`, `LIKELY`, or `UNCERTAIN` rather than binary pass/fail
- **Multi-signal evaluation** — status codes, WAF keyword detection, and response length divergence all factor into the verdict

### Authentication Support

- Bearer token
- API key (custom header name)
- Cookie / session token
- Basic Auth (username + password)

---

## Windows Desktop App (Electron)

### Prerequisites

- [Node.js](https://nodejs.org/) 18 or later

### Run from Source

```bash
git clone https://github.com/kpomin57/waf-tester.git
cd waf-tester
npm install
npm start
```

### Build Windows Installer

```bash
npm run build
```

Output appears in `dist/` as both an NSIS installer and a portable `.exe`. No prerequisites needed on the target machine — Electron bundles its own runtime.

---

## Python CLI Version

A single-file Python version that runs anywhere Python is available — Linux servers, CI/CD pipelines, Docker containers, WSL, or any environment where the Windows `.exe` is not an option.

### Prerequisites

```bash
pip install rich requests
```

### Basic Usage

```bash
python waf_tester.py --url https://target.example.com
```

Runs all 90 tests, prompts for authorization confirmation, prints color-coded results to the terminal, and saves both a JSON and HTML report to the current directory.

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--url` | Target URL **(required)** | — |
| `--suites` | Comma-separated suites to run | all |
| `--auth-type` | `none` / `bearer` / `apikey` / `cookie` / `basic` | `none` |
| `--auth-value` | Token, cookie string, or API key value | — |
| `--auth-header` | Header name for API key auth | `X-API-Key` |
| `--auth-user` | Username for Basic Auth | — |
| `--auth-pass` | Password for Basic Auth | — |
| `--no-baseline` | Disable baseline comparison | off |
| `--no-rotate-ua` | Disable User-Agent rotation | off |
| `--waf-header` | Send `X-WAF-Tester` identification header | off |
| `--output` | `terminal`, `json`, `html` (comma-separated) | all three |
| `--output-dir` | Directory to save report files | `.` |
| `--timeout` | Per-request timeout in seconds | `10` |
| `--proxy` | Proxy URL for all requests (e.g. `http://127.0.0.1:8080`) | off |
| `--confirm` | Skip the authorization confirmation prompt | off |

### Examples

```bash
# Run all suites
python waf_tester.py --url https://app.example.com

# Run OWASP and API suites only
python waf_tester.py --url https://app.example.com --suites owasp,api

# Bearer token auth
python waf_tester.py --url https://app.example.com/api \
  --auth-type bearer --auth-value eyJhbGciOiJIUzI1NiJ9...

# API key auth
python waf_tester.py --url https://app.example.com/api \
  --auth-type apikey --auth-header X-API-Key --auth-value mykey123

# Save reports to a folder, skip confirmation (CI/CD)
python waf_tester.py --url https://app.example.com \
  --output-dir ./reports --confirm

# Terminal output only — no files saved
python waf_tester.py --url https://app.example.com --output terminal

# Route traffic through Burp Suite
python waf_tester.py --url https://app.example.com --proxy http://127.0.0.1:8080
```

### Running in Docker

```bash
docker run --rm -v $(pwd)/reports:/reports \
  python:3.12-slim sh -c \
  "pip install rich requests -q && python waf_tester.py \
   --url https://target.example.com \
   --output-dir /reports --confirm"
```

### Running in CI/CD (GitHub Actions)

```yaml
- name: WAF Evaluation
  run: |
    pip install rich requests
    python waf_tester.py \
      --url ${{ secrets.WAF_TARGET_URL }} \
      --suites owasp,api,bypass \
      --output json \
      --output-dir ./reports \
      --confirm

- name: Upload report
  uses: actions/upload-artifact@v3
  with:
    name: waf-report
    path: reports/
```

---

## Burp Suite Integration

The Python CLI can route all test traffic through Burp Suite, giving you a full HTTP history of every payload WAF Tester sends. This is useful for manual inspection of requests and responses, fine-tuning payloads, troubleshooting unexpected WAF behavior, and using Burp's own scanner or repeater on interesting findings.

### How it works

Burp Suite runs a local proxy listener (default `127.0.0.1:8080`). When you point WAF Tester's proxy environment variables at that address, every request the tool makes passes through Burp before reaching the target. You see each payload in Burp's HTTP history with the full request and response — status code, headers, body — exactly as the WAF saw it.

### Setup

**1. Start Burp Suite and confirm the proxy listener is active:**

Open Burp → Proxy → Proxy Settings → confirm listener is on `127.0.0.1:8080` (or note your port if different).

**2. Export Burp's CA certificate and trust it (one-time setup):**

WAF Tester connects to HTTPS targets, so Burp needs to intercept TLS. Go to Burp → Proxy → Proxy Settings → Import/Export CA Certificate → Export as DER. Install it as a trusted root CA on your system, or set the environment variable below to skip verification (fine for lab use, not production).

**3. Run WAF Tester with `--proxy`:**

```bash
python waf_tester.py --url https://target.example.com --proxy http://127.0.0.1:8080
```

On Windows:
```cmd
python waf_tester.py --url https://target.example.com --proxy http://127.0.0.1:8080
```

You can also still use environment variables if you prefer:

```bash
HTTPS_PROXY=http://127.0.0.1:8080 HTTP_PROXY=http://127.0.0.1:8080 \
python waf_tester.py --url https://target.example.com
```

**4. Turn off Burp's interception:**

In Burp → Proxy → Intercept, make sure interception is **off** — otherwise Burp will pause on every request waiting for you to forward it manually, and WAF Tester will time out. You want Burp to passively log traffic, not intercept it.

**5. Watch the requests arrive in Burp's HTTP history:**

Each WAF Tester payload appears as a separate entry. You can right-click any request and send it to Repeater to manually tweak and resend it, or to Intruder to fuzz further.

### If you get TLS errors

If the Burp CA cert is not trusted, add `--no-verify` workaround by temporarily disabling SSL verification in the tool. Alternatively, trust the Burp CA cert system-wide or use an HTTP (not HTTPS) target for initial testing.

---

## Interpreting Results

| Score | Grade | Meaning |
|-------|-------|---------|
| 90–100% | A | Excellent — WAF blocking almost all attack vectors |
| 80–89% | B | Good — minor gaps worth investigating |
| 65–79% | C | Fair — notable bypass vectors present |
| 50–64% | D | Poor — significant protection gaps |
| < 50% | F | Critical — WAF is largely ineffective |

**Confidence levels:**
- `HIGH` — hard block status (403, 406, 429) with no ambiguity
- `LIKELY` — WAF keywords in response body, or status differs from baseline
- `UNCERTAIN` — soft block (400, 503) that could be a legitimate app error

---

## Recommended Test Workflow

1. **Run against Juice Shop with no WAF** → confirm mostly bypassed (tool is firing correctly)
2. **Run against ModSecurity/OWASP CRS** → confirm mostly blocked (scoring logic works)
3. **Run against your target WAF** → real evaluation results

```bash
# Juice Shop (no WAF — expect all bypassed)
docker run -d -p 3000:3000 bkimminich/juice-shop

# ModSecurity with OWASP CRS (expect most blocked)
docker run -d -p 80:80 owasp/modsecurity-crs:nginx
```

---

## Project Structure

```
waf-tester/
├── src/
│   ├── main.js          # Electron main process — all test logic & IPC
│   ├── preload.js       # Secure context bridge
│   └── renderer/
│       ├── index.html   # App shell
│       ├── styles.css   # Dark military/SOC UI theme
│       └── app.js       # UI logic, filters, live feed, export
├── waf_tester.py        # Python CLI — single file, no config needed
├── package.json
└── README.md
```

---

## Changelog

### v1.2.0
- Expanded from 40 to **90 tests** across **6 suites**
- Added **API Security** suite (GraphQL, JWT, mass assignment, BOLA, verb tampering)
- Added **Business Logic** suite (price manipulation, privilege escalation, forced browsing)
- Added **compliance tags** (OWASP, CWE, NIST, PCI-DSS) on every test
- Added **Framework filter** in Results view
- Added **Python CLI** (`waf_tester.py`) — single file, runs anywhere
- Full enterprise UI overhaul — SVG score rings, animated scan line, hex grid background

### v1.1.0
- Added **authentication support** (Bearer, API key, cookie, Basic Auth)
- Added **baseline comparison** and **confidence scoring** (HIGH / LIKELY / UNCERTAIN)
- Added **User-Agent rotation** across 6 realistic browser UAs
- Added **X-WAF-Tester header toggle** (opt-in, off by default)
- Added **permission checkbox** before each scan
- Fixed export toast visibility and CRLF crash in bypass tests

### v1.0.0
- Initial release — 40 tests, 4 suites, JSON + HTML export

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

*Built for security engineers who need WAF validation that goes beyond checkbox compliance.*
