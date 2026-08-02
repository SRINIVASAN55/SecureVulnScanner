# SecureVulnScanner

![CI](https://github.com/SRINIVASAN55/SecureVulnScanner/actions/workflows/ci.yml/badge.svg) ![License: MIT](https://img.shields.io/badge/License-MIT-green.svg) ![Python](https://img.shields.io/badge/python-3.8+-blue.svg)



A lightweight web application vulnerability scanner. Point it at a URL, get a prioritised list of security issues with CVE references and remediation steps.

---

## Prerequisites

| Requirement | Details |
|-------------|---------|
| Python | 3.8 or higher |
| OS | Linux, macOS, Windows |
| Internet | Required to reach the target URL |
| Permission | **Only scan systems you own or have written permission to test** |

```bash
python3 --version    # must be 3.8+
```

---

## Installation

```bash
git clone https://github.com/SRINIVASAN55/SecureVulnScanner.git
cd SecureVulnScanner
pip install -r requirements.txt
```

---

## Running It

### Basic scan — one command
```bash
python3 scanner.py --url https://yourtarget.com
python3 scanner.py -u http://testphp.vulnweb.com    # safe public test site
```
Crawls the site to depth 2 and checks for the most common vulnerabilities (SQLi, XSS, open headers, TLS issues, exposed files).

### Control crawl depth
```bash
# Shallow — homepage only
python3 scanner.py -u https://yourtarget.com --depth 1

# Deep — follow links up to 3 levels
python3 scanner.py -u https://yourtarget.com --depth 3
python3 scanner.py -u https://yourtarget.com -d 3
```

### Set request timeout
```bash
# For slow servers — increase timeout
python3 scanner.py -u https://yourtarget.com --timeout 30

# For fast networks — tighten timeout
python3 scanner.py -u https://yourtarget.com -t 5
```

### Combine all options
```bash
python3 scanner.py -u https://yourtarget.com -d 3 -t 15
```

---

## All CLI Flags

| Flag | Short | Description | Default | Example |
|------|-------|-------------|---------|---------|
| `--url` | `-u` | Target URL **(required)** | — | `-u https://example.com` |
| `--depth` | `-d` | Crawl depth | `2` | `-d 3` |
| `--timeout` | `-t` | Request timeout in seconds | `10` | `-t 20` |

---

## What It Checks

**Injection flaws**
- SQL injection — error-based, blind, time-based (`CWE-89`)
- Cross-site scripting — reflected, stored, DOM (`CWE-79`)
- Command injection via form fields and headers (`CWE-78`)
- Path traversal / local file inclusion (`CWE-22`)
- XXE in XML endpoints (`CWE-611`)

**Authentication & session**
- Default credentials against login pages
- Weak session token entropy
- Missing HttpOnly / Secure cookie flags
- Exposed admin panels (`/admin`, `/wp-admin`, `/.env`)

**Misconfiguration**
- Open HTTP methods (TRACE, PUT, DELETE)
- Missing security headers (CSP, HSTS, X-Frame-Options)
- TLS version and cipher audit
- Directory listing enabled
- Exposed `.git`, `.svn`, backup files

---

## Sample Output

```
SCAN RESULTS — example.com
──────────────────────────────────────────────────────────
[CRITICAL]  SQL Injection in /search?q=  (CWE-89)
            Payload: ' OR 1=1--
            Fix: Use parameterised queries / prepared statements

[HIGH]      Stored XSS in /comments     (CWE-79)
            Payload: <script>alert(1)</script>
            Fix: Encode output, implement Content-Security-Policy

[HIGH]      Apache 2.4.49 detected      (CVE-2021-41773)
            Path traversal + RCE if mod_cgi enabled
            Fix: Upgrade to Apache 2.4.51+

[MEDIUM]    Missing HSTS header
            Fix: Add Strict-Transport-Security: max-age=31536000

[LOW]       Directory listing on /uploads/
            Fix: Add Options -Indexes to server config
──────────────────────────────────────────────────────────
5 findings  |  1 critical  |  2 high  |  1 medium  |  1 low
```

---

## Safe Test Targets (legal to scan)

```bash
# These sites exist specifically for vulnerability scanner testing:
python3 scanner.py -u http://testphp.vulnweb.com
python3 scanner.py -u http://webscantest.com
python3 scanner.py -u https://hackthissite.org   # with account
```

---

## Troubleshooting

**`SSLError` or `certificate verify failed`**
→ Target has a bad cert. Add `--timeout 30` for slow handshakes or check if the site is actually up.

**Scan returns 0 findings on a site you know is vulnerable**
→ Increase depth: `-d 3`. Some vulnerabilities are on deeper pages.

**Scanner is very slow**
→ Reduce timeout: `-t 5`. Or the target server is just slow.

---

## Legal Notice

Only scan systems you own or have explicit written permission to test. Unauthorized scanning violates computer fraud laws in most jurisdictions. The author is not responsible for misuse.

---

**Author:** S. Srinivasan · [GitHub](https://github.com/SRINIVASAN55) · [LinkedIn](https://linkedin.com/in/srinivasan132)
