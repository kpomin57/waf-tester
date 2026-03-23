# WAF Tester

A desktop application for evaluating Web Application Firewall (WAF) solutions against real-world attack vectors.

## Test Coverage

| Suite | Count | What it tests |
|-------|-------|---------------|
| **OWASP Top 10** | 15 tests | SQL injection, XSS, path traversal, command injection, XXE, SSRF, Log4Shell, SSTI |
| **Rate Limiting** | 3 tests | Burst flood (30 concurrent), sequential flood, X-Forwarded-For IP rotation bypass |
| **Bot Detection** | 10 tests | sqlmap, Nikto, Nmap, Scrapy, curl, HeadlessChrome, python-requests, empty UA, Masscan |
| **Bypass Attempts** | 12 tests | Double URL-encode, Unicode fullwidth, HTML entities, null bytes, case variation, CRLF injection, Host header injection, method override, path tricks |

## Setup

### Prerequisites
- [Node.js](https://nodejs.org/) 18+ 
- [Git](https://git-scm.com/) (optional)

### Install & Run

```bash
# 1. Install dependencies
npm install

# 2. Run in development mode
npm start
```

### Build Windows Installer

```bash
# NSIS installer + portable .exe
npm run build

# Portable .exe only (faster)
npm run build:portable
```

Built files appear in `dist/`.

## Usage

1. Enter the target URL (e.g. `https://my-app.com/api/search`)
2. Toggle which test suites to run in the sidebar
3. Click **Run Tests**
4. Watch live results stream in; view the full table under **Results**
5. Export as JSON (machine-readable) or HTML (shareable report)

## Important Notes

- **Only test systems you own or have explicit written permission to test.**
- The tool sends actual attack payloads to the target. Ensure this is permitted.
- Rate limit tests send up to 30 simultaneous requests — be aware of impact.
- TLS certificate errors are ignored so self-signed certs work fine.
- Requests time out after 10 seconds each.

## Interpreting Results

| Score | Grade | Meaning |
|-------|-------|---------|
| 90–100% | A | Excellent — WAF is blocking almost everything |
| 80–89%  | B | Good — minor gaps to investigate |
| 65–79%  | C | Fair — notable bypass vectors present |
| 50–64%  | D | Poor — significant gaps in protection |
| < 50%   | F | Critical — WAF is largely ineffective |

A "BLOCKED" result means the WAF returned 4xx/503 or a block page body before the payload reached the origin. A "BYPASSED" result means HTTP 200 was returned — the payload may have reached the application.
