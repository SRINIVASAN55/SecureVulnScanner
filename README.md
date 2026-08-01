<div align="center">

<img src="https://capsule-render.vercel.app/api?type=rect&color=gradient&customColorList=12&height=80&text=🔍%20SecureVulnScanner&fontSize=30&fontColor=ffffff" width="100%"/>

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010-red?style=for-the-badge)](https://owasp.org/www-project-top-ten/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Research-orange?style=for-the-badge)]()

**An OWASP ZAP-inspired web application vulnerability scanner built in Python.**  
Detects OWASP Top 10 vulnerabilities through automated crawling, active testing, and generates detailed HTML reports.

</div>

---

## ✨ Features

| Feature | Description |
|---|---|
| 🕷️ **Web Crawler** | Recursively crawls target web apps to discover all endpoints and forms |
| 💉 **SQL Injection** | Error-based SQLi detection via form fuzzing with payloads |
| 🔥 **XSS Detection** | Reflected XSS via payload injection into all input fields |
| 🔒 **Security Headers** | Checks for CSP, HSTS, X-Frame-Options, and 6 other critical headers |
| 🔑 **Sensitive Files** | Scans for exposed .env, .git/config, wp-config.php, backup files |
| 📂 **Dir Listing** | Detects open directory listing on common paths |
| 🔀 **Open Redirect** | Identifies open redirect vulnerabilities via parameter fuzzing |
| 🌐 **SSL/TLS** | Detects missing HTTPS and unencrypted transport |
| 📄 **HTML Reports** | Professional color-coded vulnerability reports with remediation |

---

## 🚀 Quick Start

```bash
# Clone
git clone https://github.com/SRINIVASAN55/SecureVulnScanner.git
cd SecureVulnScanner

# Install dependencies
pip install -r requirements.txt

# Scan a target (use only on systems you own or have permission to test)
python scanner.py -u https://testphp.vulnweb.com

# Deeper scan with custom timeout
python scanner.py -u https://example.com -d 3 -t 15
```

---

## 📋 Usage

```
usage: scanner.py [-h] -u URL [-d DEPTH] [-t TIMEOUT]

  -u URL,      --url URL        Target URL (required)
  -d DEPTH,    --depth DEPTH    Crawl depth, default=2
  -t TIMEOUT,  --timeout TIMEOUT Request timeout in seconds, default=10
```

---

## 📊 Sample Output

```
╔═══════════════════════════════════════════════════╗
║       SecureVulnScanner v1.0                      ║
║       OWASP Top 10 Web Vulnerability Scanner      ║
╚═══════════════════════════════════════════════════╝

[*] Target  : https://testphp.vulnweb.com
[*] Phase 1: Crawling target... Found 23 URLs
[*] Phase 2: Scanning for vulnerabilities...

[CRITICAL] SQL Injection
           URL: https://testphp.vulnweb.com/search.php
           OWASP: A03:2021 - Injection
           Fix: Use parameterized queries

[HIGH] Missing Security Header: Content-Security-Policy
[MEDIUM] Missing Security Header: X-Frame-Options
[HIGH] Sensitive File Exposed: /.env

CRITICAL: 1 | HIGH: 3 | MEDIUM: 4 | LOW: 0 | INFO: 2

[✓] HTML Report saved: vuln_report_testphp.vulnweb.com_1234567890.html
```

---

## 🛡️ OWASP Top 10 Coverage

| ID | Vulnerability | Status |
|---|---|---|
| A01 | Broken Access Control | ✅ Open Redirect check |
| A02 | Cryptographic Failures | ✅ HTTP/HTTPS check |
| A03 | Injection (SQLi + XSS) | ✅ Full payload fuzzing |
| A05 | Security Misconfiguration | ✅ Headers + Dir Listing + Files |
| A07 | Auth Failures | 🔜 Coming soon |
| A09 | Logging Failures | 🔜 Coming soon |

---

## ⚠️ Legal Disclaimer

> **This tool is for authorized security testing and educational purposes only.**  
> Only use SecureVulnScanner on systems you own or have explicit written permission to test.  
> Unauthorized scanning is illegal and unethical.

---

## 📄 License

MIT License © 2024 [Srinivasan S](https://github.com/SRINIVASAN55)
