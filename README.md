```
 ██████╗ ███████╗ ██████╗██╗   ██╗██████╗ ███████╗
██╔════╝ ██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝
╚█████╗  █████╗  ██║     ██║   ██║██████╔╝█████╗  
 ╚═══██╗ ██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  
██████╔╝ ███████╗╚██████╗╚██████╔╝██║  ██║███████╗
╚═════╝  ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
          V U L N   S C A N N E R
```

<p align="center">
  <img src="https://img.shields.io/badge/⚠_AUTHORIZED_USE_ONLY-FF0000?style=for-the-badge&labelColor=1a0000"/>
  <img src="https://img.shields.io/badge/OWASP-Top%2010%20Coverage-FF6600?style=for-the-badge&logo=owasp&logoColor=white"/>
  <img src="https://img.shields.io/badge/Python-3.8+-FFD700?style=for-the-badge&logo=python&logoColor=black"/>
  <img src="https://img.shields.io/badge/Reports-HTML_PDF-FF4444?style=for-the-badge"/>
</p>

---

> **"The best defense is knowing how to attack."**  
> A web application vulnerability scanner built in pure Python — crawls, fuzzes, and reports like OWASP ZAP.

---

### 💀 What It Hunts

```
TARGET ACQUIRED: https://target.com
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[A01] Broken Access Control ............ SCANNING
[A02] Cryptographic Failures ........... SCANNING  
[A03] Injection (SQLi + XSS) ........... ████████ FOUND 🔴
[A05] Security Misconfiguration ........ ████████ FOUND 🟡
[A07] Auth & Session Failures .......... SCANNING
[A09] Logging & Monitoring Failures .... SCANNING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CRITICAL: 2  HIGH: 4  MEDIUM: 6  LOW: 1
```

---

### 🔧 Install & Run

```bash
git clone https://github.com/SRINIVASAN55/SecureVulnScanner
cd SecureVulnScanner && pip install -r requirements.txt

# Basic scan
python scanner.py -u https://testphp.vulnweb.com

# Deep scan — crawl 3 levels, 15s timeout
python scanner.py -u https://target.com -d 3 -t 15
```

---

### 🧪 Vulnerability Checks

| Check | Method | OWASP |
|---|---|---|
| SQL Injection | Error-based form fuzzing with 6 payloads | A03 |
| Reflected XSS | Payload injection into all inputs | A03 |
| Missing Security Headers | CSP, HSTS, X-Frame-Options, 6 more | A05 |
| Sensitive File Exposure | `.env`, `.git`, `wp-config`, `dump.sql` | A05 |
| Directory Listing | Common paths: `/admin/`, `/backup/` | A05 |
| Open Redirect | Parameter fuzzing on redirect params | A01 |
| Unencrypted Transport | HTTP vs HTTPS detection | A02 |
| Info Disclosure | `Server`, `X-Powered-By` headers | A05 |

---

### 📄 HTML Report Output

```
┌────────────────────────────────────────────────────┐
│  🔴 CRITICAL  SQL Injection — /search.php           │
│  OWASP: A03:2021   Payload: ' OR 1=1--             │
│  Fix: Use parameterized queries                     │
├────────────────────────────────────────────────────┤
│  🟡 MEDIUM    Missing Header: X-Frame-Options       │
│  OWASP: A05:2021                                   │
│  Fix: Add X-Frame-Options: DENY                    │
└────────────────────────────────────────────────────┘
```

---

> ⚠️ **Legal:** Only scan systems you own or have written permission to test. Unauthorized scanning is illegal.

<p align="center">Built by <a href="https://github.com/SRINIVASAN55">SRINIVASAN55</a> · <a href="https://linkedin.com/in/srinivasan132">LinkedIn</a></p>
