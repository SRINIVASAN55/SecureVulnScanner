#!/usr/bin/env python3
"""
SecureVulnScanner - OWASP ZAP-style Web Vulnerability Scanner
Author: Srinivasan S (SRINIVASAN55)
Description: Scans web applications for OWASP Top 10 vulnerabilities
"""

import sys
import time
import socket
import argparse
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime

try:
    import requests
    from bs4 import BeautifulSoup
    DEPS_OK = True
except ImportError:
    DEPS_OK = False

# ─── ANSI Colors ────────────────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

BANNER = f"""
{C.GREEN}{C.BOLD}
  ╔═══════════════════════════════════════════════════╗
  ║       SecureVulnScanner v1.0                      ║
  ║       OWASP Top 10 Web Vulnerability Scanner      ║
  ║       Author: SRINIVASAN55                        ║
  ╚═══════════════════════════════════════════════════╝
{C.RESET}"""

# ─── Data Models ─────────────────────────────────────────────────────────────
@dataclass
class Vulnerability:
    vuln_id:     str
    name:        str
    severity:    str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    description: str
    url:         str
    evidence:    str = ""
    remediation: str = ""
    owasp_ref:   str = ""

@dataclass
class ScanReport:
    target:    str
    started:   str
    finished:  str = ""
    findings:  List[Vulnerability] = field(default_factory=list)

    @property
    def critical(self): return [f for f in self.findings if f.severity == "CRITICAL"]
    @property
    def high(self):     return [f for f in self.findings if f.severity == "HIGH"]
    @property
    def medium(self):   return [f for f in self.findings if f.severity == "MEDIUM"]
    @property
    def low(self):      return [f for f in self.findings if f.severity == "LOW"]
    @property
    def info(self):     return [f for f in self.findings if f.severity == "INFO"]

# ─── Scanner Core ─────────────────────────────────────────────────────────────
class SecureVulnScanner:
    SQLI_PAYLOADS = ["'", "''", "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1", "'; DROP TABLE users--"]
    XSS_PAYLOADS  = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                     "'\"><script>alert(1)</script>", "<svg/onload=alert(1)>"]
    CMD_PAYLOADS  = ["; ls", "| id", "`id`", "$(id)", "; cat /etc/passwd"]
    PATH_PAYLOADS = ["/../../../etc/passwd", "/../../windows/system32/drivers/etc/hosts",
                     "/%2e%2e/%2e%2e/etc/passwd"]
    SENSITIVE_HEADERS = {
        "X-Powered-By": "HIGH",
        "Server": "MEDIUM",
        "X-AspNet-Version": "MEDIUM",
        "X-AspNetMvc-Version": "MEDIUM",
    }
    SECURITY_HEADERS_REQUIRED = [
        "Content-Security-Policy", "X-Frame-Options",
        "X-Content-Type-Options", "Strict-Transport-Security",
        "Referrer-Policy", "Permissions-Policy",
    ]

    def __init__(self, target: str, timeout: int = 10, depth: int = 2):
        self.target   = target.rstrip("/")
        self.timeout  = timeout
        self.depth    = depth
        self.session  = requests.Session() if DEPS_OK else None
        self.visited: set  = set()
        self.report   = ScanReport(target=target, started=datetime.now().isoformat())
        if self.session:
            self.session.headers.update({
                "User-Agent": "SecureVulnScanner/1.0 (Security Assessment Tool)"
            })
            self.session.verify = False

    # ── Crawling ────────────────────────────────────────────────────────────
    def crawl(self, url: str, current_depth: int = 0) -> List[str]:
        if current_depth > self.depth or url in self.visited:
            return []
        self.visited.add(url)
        links = [url]
        try:
            r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            soup = BeautifulSoup(r.text, "html.parser")
            for tag in soup.find_all(["a", "form"]):
                href = tag.get("href") or tag.get("action", "")
                if href and not href.startswith(("mailto:", "tel:", "#", "javascript:")):
                    full = urllib.parse.urljoin(url, href)
                    if full.startswith(self.target) and full not in self.visited:
                        links += self.crawl(full, current_depth + 1)
        except Exception:
            pass
        return links

    def _get_forms(self, url: str) -> list:
        try:
            r = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(r.text, "html.parser")
            return soup.find_all("form")
        except Exception:
            return []

    def _submit_form(self, url: str, form, payload: str):
        action = form.get("action") or url
        method = form.get("method", "get").lower()
        data   = {}
        for inp in form.find_all("input"):
            name = inp.get("name")
            if name:
                data[name] = payload
        try:
            if method == "post":
                return self.session.post(urllib.parse.urljoin(url, action), data=data, timeout=self.timeout)
            return self.session.get(urllib.parse.urljoin(url, action), params=data, timeout=self.timeout)
        except Exception:
            return None

    # ── Checks ──────────────────────────────────────────────────────────────
    def check_sql_injection(self, url: str):
        self._log("  🔎 Checking SQL Injection...", C.CYAN)
        forms = self._get_forms(url)
        errors = ["sql syntax", "mysql_fetch", "ORA-", "syntax error", "SQLSTATE", "unclosed quotation"]
        for form in forms:
            for payload in self.SQLI_PAYLOADS:
                r = self._submit_form(url, form, payload)
                if r:
                    lower = r.text.lower()
                    if any(e.lower() in lower for e in errors):
                        self.report.findings.append(Vulnerability(
                            vuln_id="OWASP-A03", name="SQL Injection",
                            severity="CRITICAL", url=url,
                            description="SQL injection vulnerability detected via error-based detection.",
                            evidence=f"Payload: {payload}",
                            remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                            owasp_ref="A03:2021 - Injection"
                        ))
                        return

    def check_xss(self, url: str):
        self._log("  🔎 Checking XSS...", C.CYAN)
        forms = self._get_forms(url)
        for form in forms:
            for payload in self.XSS_PAYLOADS:
                r = self._submit_form(url, form, payload)
                if r and payload in r.text:
                    self.report.findings.append(Vulnerability(
                        vuln_id="OWASP-A03-XSS", name="Cross-Site Scripting (XSS)",
                        severity="HIGH", url=url,
                        description="Reflected XSS vulnerability — user input reflected unsanitized in response.",
                        evidence=f"Payload reflected: {payload}",
                        remediation="Encode output, use Content-Security-Policy header, sanitize all user input.",
                        owasp_ref="A03:2021 - Injection (XSS)"
                    ))
                    return

    def check_security_headers(self, url: str):
        self._log("  🔎 Checking Security Headers...", C.CYAN)
        try:
            r = self.session.get(url, timeout=self.timeout)
            headers = {k.lower(): v for k, v in r.headers.items()}
            # Missing security headers
            for h in self.SECURITY_HEADERS_REQUIRED:
                if h.lower() not in headers:
                    self.report.findings.append(Vulnerability(
                        vuln_id="OWASP-A05", name=f"Missing Security Header: {h}",
                        severity="MEDIUM", url=url,
                        description=f"The HTTP response is missing the '{h}' security header.",
                        remediation=f"Add '{h}' header to all HTTP responses.",
                        owasp_ref="A05:2021 - Security Misconfiguration"
                    ))
            # Information-leaking headers
            for h, sev in self.SENSITIVE_HEADERS.items():
                if h.lower() in headers:
                    self.report.findings.append(Vulnerability(
                        vuln_id="OWASP-A05-INFO", name=f"Information Disclosure: {h}",
                        severity=sev, url=url,
                        description=f"Header '{h}: {r.headers[h]}' discloses server technology.",
                        remediation=f"Remove or obfuscate the '{h}' response header.",
                        owasp_ref="A05:2021 - Security Misconfiguration"
                    ))
        except Exception:
            pass

    def check_ssl_tls(self, url: str):
        self._log("  🔎 Checking SSL/TLS...", C.CYAN)
        if url.startswith("http://"):
            self.report.findings.append(Vulnerability(
                vuln_id="OWASP-A02-SSL", name="No HTTPS / Unencrypted Transport",
                severity="HIGH", url=url,
                description="Target is served over plain HTTP without encryption.",
                remediation="Enable HTTPS with a valid TLS certificate. Redirect all HTTP traffic to HTTPS.",
                owasp_ref="A02:2021 - Cryptographic Failures"
            ))

    def check_open_redirect(self, url: str):
        self._log("  🔎 Checking Open Redirect...", C.CYAN)
        payloads = ["//evil.com", "https://evil.com", "http://evil.com"]
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        redirect_params = [p for p in params if any(k in p.lower() for k in ["url","redirect","next","return","goto","dest"])]
        for param in redirect_params:
            for payload in payloads:
                test_params = {**{k: v[0] for k, v in params.items()}, param: payload}
                test_url = parsed._replace(query=urllib.parse.urlencode(test_params)).geturl()
                try:
                    r = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
                    loc = r.headers.get("Location", "")
                    if "evil.com" in loc:
                        self.report.findings.append(Vulnerability(
                            vuln_id="OWASP-A01-REDIR", name="Open Redirect",
                            severity="MEDIUM", url=url,
                            description=f"Open redirect via '{param}' parameter.",
                            evidence=f"Redirected to: {loc}",
                            remediation="Validate redirect URLs against a strict whitelist.",
                            owasp_ref="A01:2021 - Broken Access Control"
                        ))
                        return
                except Exception:
                    pass

    def check_directory_listing(self, url: str):
        self._log("  🔎 Checking Directory Listing...", C.CYAN)
        dirs = ["/uploads/", "/backup/", "/admin/", "/config/", "/logs/", "/tmp/", "/.git/"]
        for d in dirs:
            try:
                r = self.session.get(self.target + d, timeout=self.timeout)
                if r.status_code == 200 and any(k in r.text for k in ["Index of", "Parent Directory", "[DIR]"]):
                    self.report.findings.append(Vulnerability(
                        vuln_id="OWASP-A05-DIR", name=f"Directory Listing Enabled: {d}",
                        severity="MEDIUM", url=self.target + d,
                        description=f"Directory listing is enabled at '{d}', exposing file structure.",
                        remediation="Disable directory listing in web server config (Options -Indexes in Apache).",
                        owasp_ref="A05:2021 - Security Misconfiguration"
                    ))
            except Exception:
                pass

    def check_sensitive_files(self, url: str):
        self._log("  🔎 Checking Sensitive File Exposure...", C.CYAN)
        files = {
            "/.env": "CRITICAL", "/.git/config": "HIGH", "/config.php": "HIGH",
            "/wp-config.php": "HIGH", "/database.yml": "HIGH", "/credentials.json": "CRITICAL",
            "/backup.zip": "HIGH", "/dump.sql": "CRITICAL", "/.htpasswd": "HIGH",
            "/robots.txt": "INFO", "/sitemap.xml": "INFO",
        }
        for path, severity in files.items():
            try:
                r = self.session.get(self.target + path, timeout=self.timeout)
                if r.status_code == 200 and len(r.text) > 0:
                    self.report.findings.append(Vulnerability(
                        vuln_id="OWASP-A05-FILE", name=f"Sensitive File Exposed: {path}",
                        severity=severity, url=self.target + path,
                        description=f"Sensitive file '{path}' is publicly accessible.",
                        remediation=f"Restrict access to '{path}' via server config or move outside web root.",
                        owasp_ref="A05:2021 - Security Misconfiguration"
                    ))
            except Exception:
                pass

    # ── Helpers ─────────────────────────────────────────────────────────────
    def _log(self, msg: str, color: str = ""):
        print(f"{color}{msg}{C.RESET}", flush=True)

    def _sev_color(self, sev: str) -> str:
        return {
            "CRITICAL": C.RED + C.BOLD,
            "HIGH":     C.RED,
            "MEDIUM":   C.YELLOW,
            "LOW":      C.GREEN,
            "INFO":     C.CYAN,
        }.get(sev, "")

    # ── Main Scan ────────────────────────────────────────────────────────────
    def run(self):
        if not DEPS_OK:
            print(f"{C.RED}[!] Install deps: pip install requests beautifulsoup4{C.RESET}")
            sys.exit(1)

        import urllib3; urllib3.disable_warnings()
        print(BANNER)
        print(f"{C.BOLD}[*] Target  : {self.target}{C.RESET}")
        print(f"{C.BOLD}[*] Started : {self.report.started}{C.RESET}")
        print(f"{C.BOLD}[*] Depth   : {self.depth}{C.RESET}\n")

        # Phase 1: Crawl
        self._log("[+] Phase 1: Crawling target...", C.GREEN)
        urls = self.crawl(self.target)
        self._log(f"    Found {len(urls)} URLs\n", C.GREEN)

        # Phase 2: Scan
        self._log("[+] Phase 2: Scanning for vulnerabilities...", C.GREEN)
        self.check_ssl_tls(self.target)
        for url in urls:
            self._log(f"\n[→] Scanning: {url}", C.BOLD)
            self.check_sql_injection(url)
            self.check_xss(url)
            self.check_security_headers(url)
            self.check_open_redirect(url)
            self.check_directory_listing(url)
            self.check_sensitive_files(url)
            time.sleep(0.3)  # Be polite

        self.report.finished = datetime.now().isoformat()

        # Phase 3: Report
        self._print_report()
        self._generate_html_report()

    def _print_report(self):
        r = self.report
        print(f"\n{C.BOLD}{'═'*60}{C.RESET}")
        print(f"{C.BOLD}  SCAN REPORT — {r.target}{C.RESET}")
        print(f"{C.BOLD}{'═'*60}{C.RESET}")
        print(f"  Started : {r.started}")
        print(f"  Finished: {r.finished}")
        print(f"  URLs Scanned: {len(self.visited)}")
        print(f"\n  {C.RED}{C.BOLD}CRITICAL: {len(r.critical)}{C.RESET}  "
              f"{C.RED}HIGH: {len(r.high)}{C.RESET}  "
              f"{C.YELLOW}MEDIUM: {len(r.medium)}{C.RESET}  "
              f"{C.GREEN}LOW: {len(r.low)}{C.RESET}  "
              f"{C.CYAN}INFO: {len(r.info)}{C.RESET}")
        print(f"\n{C.BOLD}  FINDINGS:{C.RESET}")
        for i, v in enumerate(r.findings, 1):
            sc = self._sev_color(v.severity)
            print(f"\n  [{i}] {sc}[{v.severity}]{C.RESET} {C.BOLD}{v.name}{C.RESET}")
            print(f"      URL        : {v.url}")
            print(f"      OWASP Ref  : {v.owasp_ref}")
            print(f"      Description: {v.description}")
            if v.evidence:
                print(f"      Evidence   : {v.evidence}")
            print(f"      Fix        : {v.remediation}")
        print(f"\n{C.BOLD}{'═'*60}{C.RESET}")

    def _generate_html_report(self):
        r = self.report
        filename = f"vuln_report_{urllib.parse.urlparse(r.target).netloc}_{int(time.time())}.html"
        sev_counts = {
            "CRITICAL": len(r.critical), "HIGH": len(r.high),
            "MEDIUM": len(r.medium), "LOW": len(r.low), "INFO": len(r.info)
        }
        sev_colors = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#16a34a", "INFO": "#0891b2"}
        findings_html = ""
        for i, v in enumerate(r.findings, 1):
            col = sev_colors.get(v.severity, "#888")
            findings_html += f"""
            <div class="finding">
              <div class="finding-header" style="border-left: 4px solid {col}">
                <span class="sev-badge" style="background:{col}">{v.severity}</span>
                <strong>{v.name}</strong>
                <span class="owasp-tag">{v.owasp_ref}</span>
              </div>
              <div class="finding-body">
                <p><strong>URL:</strong> <code>{v.url}</code></p>
                <p><strong>Description:</strong> {v.description}</p>
                {"<p><strong>Evidence:</strong> <code>" + v.evidence + "</code></p>" if v.evidence else ""}
                <p><strong>Remediation:</strong> {v.remediation}</p>
              </div>
            </div>"""
        badges = "".join(f'<div class="badge" style="background:{sev_colors[k]}">{k}<br><span>{sev_counts[k]}</span></div>' for k in sev_counts)
        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>SecureVulnScanner Report</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #e6edf3; }}
header {{ background: #161b22; border-bottom: 2px solid #00ff41; padding: 24px 40px; }}
header h1 {{ color: #00ff41; font-size: 28px; }}
header p {{ color: #8b949e; margin-top: 4px; }}
.summary {{ display: flex; gap: 16px; padding: 24px 40px; flex-wrap: wrap; }}
.badge {{ background: #21262d; border-radius: 10px; padding: 16px 24px; text-align:center; font-weight: bold; font-size: 13px; color: white; text-transform: uppercase; letter-spacing: 1px; }}
.badge span {{ display: block; font-size: 32px; margin-top: 6px; }}
.section {{ padding: 0 40px 40px; }}
h2 {{ color: #00ff41; font-size: 20px; margin-bottom: 16px; border-bottom: 1px solid #21262d; padding-bottom: 8px; }}
.finding {{ background: #161b22; border-radius: 8px; margin-bottom: 16px; overflow: hidden; }}
.finding-header {{ display: flex; align-items: center; gap: 12px; padding: 14px 20px; background: #0d1117; }}
.finding-body {{ padding: 16px 20px; }}
.finding-body p {{ margin-bottom: 8px; line-height: 1.6; }}
.sev-badge {{ color: white; font-weight: bold; font-size: 11px; padding: 4px 10px; border-radius: 4px; text-transform: uppercase; }}
.owasp-tag {{ margin-left: auto; font-size: 12px; color: #8b949e; }}
code {{ background: #21262d; padding: 2px 6px; border-radius: 4px; font-size: 13px; word-break: break-all; }}
</style></head>
<body>
<header>
  <h1>🔍 SecureVulnScanner Report</h1>
  <p>Target: {r.target} &nbsp;|&nbsp; Scanned: {r.started} &nbsp;|&nbsp; Total Findings: {len(r.findings)}</p>
</header>
<div class="summary">{badges}</div>
<div class="section"><h2>Vulnerability Findings</h2>{findings_html if findings_html else "<p style='color:#8b949e'>No vulnerabilities detected.</p>"}</div>
</body></html>"""
        with open(filename, "w") as f:
            f.write(html)
        print(f"\n{C.GREEN}[✓] HTML Report saved: {filename}{C.RESET}")

# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="SecureVulnScanner — OWASP Top 10 Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py -u https://example.com
  python scanner.py -u https://testphp.vulnweb.com -d 3 -t 15
  python scanner.py -u http://target.com --output-html
        """
    )
    parser.add_argument("-u", "--url",     required=True, help="Target URL (e.g. https://example.com)")
    parser.add_argument("-d", "--depth",   type=int, default=2, help="Crawl depth (default: 2)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    args = parser.parse_args()

    scanner = SecureVulnScanner(target=args.url, timeout=args.timeout, depth=args.depth)
    scanner.run()

if __name__ == "__main__":
    main()
