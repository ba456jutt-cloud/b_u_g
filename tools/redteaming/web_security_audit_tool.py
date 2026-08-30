"""
Web Security Headers & OWASP Audit Tool
Performs a comprehensive passive security check on a web URL including:
- Security headers (OWASP recommendations)
- CORS policy
- Cookie security flags
- Information disclosure
- API endpoint detection
"""
import requests
from urllib.parse import urlparse
from tools.base import Tool


class WebSecurityAuditTool(Tool):
    name = "web_security_audit"
    description = (
        "Performs a comprehensive passive web security audit on a URL. "
        "Checks OWASP security headers, CORS misconfigurations, cookie security flags, "
        "information disclosure in headers, and common API endpoint exposure. "
        "Does NOT perform active attacks — safe to run on any target."
    )
    parameters = {
        "url": "Target URL to audit (e.g. https://example.com or http://165.232.76.99:5000)",
        "check_common_paths": "Whether to check common sensitive paths like /admin, /api/docs (default: true)"
    }

    # Security headers and what they protect against
    SECURITY_HEADERS = {
        "Content-Security-Policy":          ("CRITICAL", "Prevents XSS and data injection attacks"),
        "Strict-Transport-Security":        ("HIGH",     "Enforces HTTPS (HSTS)"),
        "X-Frame-Options":                  ("MEDIUM",   "Prevents clickjacking attacks"),
        "X-Content-Type-Options":           ("MEDIUM",   "Prevents MIME-type sniffing"),
        "Referrer-Policy":                  ("MEDIUM",   "Controls referrer information leakage"),
        "Permissions-Policy":               ("LOW",      "Controls browser feature access"),
        "X-XSS-Protection":                 ("LOW",      "Legacy XSS filter (deprecated but informational)"),
        "Cross-Origin-Opener-Policy":       ("LOW",      "Isolates browsing context"),
        "Cross-Origin-Resource-Policy":     ("LOW",      "Controls cross-origin resource loading"),
    }

    # Paths that commonly expose sensitive info
    SENSITIVE_PATHS = [
        "/admin", "/api/docs", "/api/v1/docs", "/swagger", "/swagger-ui.html",
        "/swagger.json", "/openapi.json", "/.env", "/config", "/debug",
        "/health", "/metrics", "/actuator", "/phpinfo.php", "/server-status",
        "/api", "/graphql", "/console"
    ]

    def execute(self, url: str, check_common_paths: bool = True, **kwargs) -> str:
        results = []
        findings = []

        # Normalize URL
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        results.append(f"=== Web Security Audit: {url} ===\n")

        try:
            headers_req = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityAudit/1.0"
            }
            resp = requests.get(url, headers=headers_req, timeout=10, verify=False, allow_redirects=True)
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}

        except requests.exceptions.ConnectionError:
            try:
                resp = requests.get(url, headers=headers_req, timeout=10, verify=False)
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            except Exception as e2:
                return f"Error: Cannot connect to {url}: {e2}"
        except requests.exceptions.Timeout:
            return f"Error: Connection to {url} timed out after 10 seconds."
        except Exception as e:
            return f"Error: {type(e).__name__}: {str(e)}"

        # 1. Basic Info
        results.append("--- [1] Basic Information ---")
        results.append(f"HTTP Status:    {resp.status_code}")
        results.append(f"Final URL:      {resp.url}")
        server = resp.headers.get("Server", "Not disclosed")
        powered_by = resp.headers.get("X-Powered-By", "Not disclosed")
        results.append(f"Server:         {server}")
        results.append(f"X-Powered-By:   {powered_by}")

        if server != "Not disclosed":
            findings.append(f"🟡 MEDIUM - Server version disclosed in header: '{server}' — attackers can target known CVEs for this version.")
        if powered_by != "Not disclosed":
            findings.append(f"🟡 MEDIUM - Technology disclosed via X-Powered-By: '{powered_by}' — reveals backend stack.")

        # 2. Security Headers Check
        results.append("\n--- [2] Security Headers (OWASP) ---")
        missing_critical = []
        for header, (severity, description) in self.SECURITY_HEADERS.items():
            if header.lower() in resp_headers:
                val = resp_headers[header.lower()]
                results.append(f"✅ PRESENT  | {header}: {val[:80]}")
            else:
                emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")
                results.append(f"❌ MISSING  | {header} [{severity}] — {description}")
                findings.append(f"{emoji} {severity} - Missing header '{header}': {description}")
                if severity == "CRITICAL":
                    missing_critical.append(header)

        # 3. CORS Check
        results.append("\n--- [3] CORS Policy ---")
        cors_header = resp_headers.get("access-control-allow-origin", None)
        if cors_header:
            if cors_header == "*":
                results.append(f"🔴 CORS: Access-Control-Allow-Origin: * (WILDCARD - Any origin allowed!)")
                findings.append("🔴 CRITICAL - CORS wildcard '*' allows any website to make cross-origin requests. Data theft risk.")
            else:
                results.append(f"✅ CORS: Access-Control-Allow-Origin: {cors_header}")
        else:
            results.append("ℹ️  CORS: No Access-Control-Allow-Origin header (may be intentional for non-API sites)")

        # 4. Cookie Security
        results.append("\n--- [4] Cookie Security ---")
        set_cookie = resp.headers.get("Set-Cookie", "")
        if set_cookie:
            cookie_issues = []
            if "httponly" not in set_cookie.lower():
                cookie_issues.append("Missing HttpOnly flag (XSS can steal cookie)")
                findings.append("🟠 HIGH - Cookie missing HttpOnly flag — vulnerable to XSS-based session theft.")
            if "secure" not in set_cookie.lower():
                cookie_issues.append("Missing Secure flag (cookie sent over HTTP)")
                findings.append("🟠 HIGH - Cookie missing Secure flag — cookie transmitted over plain HTTP.")
            if "samesite" not in set_cookie.lower():
                cookie_issues.append("Missing SameSite attribute (CSRF risk)")
                findings.append("🟡 MEDIUM - Cookie missing SameSite attribute — potential CSRF vulnerability.")

            if cookie_issues:
                results.append(f"⚠️  Cookie issues: {'; '.join(cookie_issues)}")
                results.append(f"   Raw: {set_cookie[:200]}")
            else:
                results.append(f"✅ Cookie properly secured: {set_cookie[:150]}")
        else:
            results.append("ℹ️  No Set-Cookie header on root path (may be set on login endpoints)")

        # 5. Common Sensitive Paths
        if check_common_paths:
            results.append("\n--- [5] Sensitive Path Exposure ---")
            exposed = []
            for path in self.SENSITIVE_PATHS:
                try:
                    r = requests.get(
                        base_url + path,
                        headers=headers_req,
                        timeout=4,
                        allow_redirects=False
                    )
                    if r.status_code in [200, 201, 301, 302, 403]:
                        status_info = f"HTTP {r.status_code}"
                        if r.status_code == 200:
                            exposed.append((path, status_info, "ACCESSIBLE"))
                            findings.append(f"🔴 CRITICAL - Exposed path '{path}' returns {r.status_code}. May leak sensitive data.")
                        elif r.status_code == 403:
                            exposed.append((path, status_info, "EXISTS (Forbidden)"))
                        elif r.status_code in [301, 302]:
                            exposed.append((path, status_info + f" → {r.headers.get('Location', '?')}", "REDIRECT"))
                except Exception:
                    continue

            if exposed:
                for path, status, access in exposed:
                    marker = "🔴" if access == "ACCESSIBLE" else "🟡"
                    results.append(f"{marker} {path:30s} | {status} | {access}")
            else:
                results.append("✅ No common sensitive paths found accessible.")

        # 6. Summary of Findings
        results.append("\n" + "="*50)
        results.append("=== SECURITY FINDINGS SUMMARY ===")
        if findings:
            for f in findings:
                results.append(f"  {f}")
        else:
            results.append("  ✅ No significant issues found.")

        results.append(f"\nTotal Issues Found: {len(findings)}")
        results.append("="*50)

        return "\n".join(results)
