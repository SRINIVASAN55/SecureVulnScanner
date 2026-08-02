# SecureVulnScanner

A lightweight web application vulnerability scanner. Point it at a URL, get a prioritised list of security issues with CVE references and remediation steps.

---

## Scan coverage

**Injection**
- SQL injection (error-based, blind, time-based) — `T1190`, `CWE-89`
- XSS (reflected, stored, DOM) — `CWE-79`
- Command injection via form fields and headers — `CWE-78`
- Path traversal / LFI — `CWE-22`
- XXE in XML endpoints — `CWE-611`

**Authentication & Session**
- Default credentials against login pages
- Weak session token entropy detection
- Missing HttpOnly / Secure cookie flags
- Exposed admin panels (`/admin`, `/wp-admin`, `/.env`, etc.)

**Configuration**
- Open HTTP methods (TRACE, PUT, DELETE)
- Missing security headers (CSP, HSTS, X-Frame-Options)
- TLS version and cipher audit
- Directory listing enabled
- Exposed `.git`, `.svn`, backup files

**CVE Matching**
- Banner fingerprinting against NVD CVE database
- Version-based vulnerability lookup (Apache, nginx, PHP, WordPress, etc.)

---

## Usage

```bash
git clone https://github.com/SRINIVASAN55/SecureVulnScanner
cd SecureVulnScanner
pip install -r requirements.txt

# Basic scan
python scanner.py --url https://target.example.com

# Full scan with all modules
python scanner.py --url https://target.example.com --full

# Scan with custom wordlist
python scanner.py --url https://target.example.com --wordlist custom.txt

# Output formats
python scanner.py --url https://target.example.com --output report.html
python scanner.py --url https://target.example.com --output report.json
```

---

## Sample report

```
SCAN RESULTS — target.example.com
──────────────────────────────────────────────────────────
[CRITICAL]  SQL Injection in /search?q=  (CWE-89)
            Payload: ' OR 1=1--
            Fix: Use parameterised queries

[HIGH]      Stored XSS in /comments     (CWE-79)
            Payload: <script>alert(1)</script>
            Fix: Encode output, implement CSP

[HIGH]      Apache 2.4.49 detected      (CVE-2021-41773)
            Path traversal + RCE if mod_cgi enabled
            Fix: Upgrade to 2.4.51+

[MEDIUM]    Missing HSTS header
            Fix: Strict-Transport-Security: max-age=31536000

[LOW]       Directory listing on /uploads/
            Fix: Disable in server config
──────────────────────────────────────────────────────────
5 findings  |  1 critical  |  2 high  |  1 medium  |  1 low
```

---

## Legal

Only scan systems you own or have written permission to test. Unauthorized scanning is illegal in most jurisdictions.

---

**Author:** S. Srinivasan · [GitHub](https://github.com/SRINIVASAN55) · [LinkedIn](https://linkedin.com/in/srinivasan132)
