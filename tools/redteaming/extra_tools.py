"""
WPScan — WordPress Vulnerability Scanner
For any WordPress site: finds vulnerable plugins, themes, user enumeration, weak passwords.
"""
import subprocess
from tools.base import Tool

class WpScanTool(Tool):
    name = "wpscan_wordpress"
    description = (
        "Scans WordPress sites for vulnerabilities: outdated plugins with CVEs, "
        "vulnerable themes, user enumeration (finds admin usernames), "
        "exposed wp-config.php, xmlrpc.php brute-force surface, "
        "and known WordPress core vulnerabilities. "
        "Only use on targets running WordPress (check WhatWeb first)."
    )
    parameters = {
        "url": "WordPress site URL (e.g. https://example.com)",
        "enumerate": "What to enumerate: 'vp' (vulnerable plugins), 'vt' (vulnerable themes), 'u' (users), 'ap,at,u' (all). Default: vp,vt,u"
    }

    def execute(self, url: str, enumerate: str = "vp,vt,u", **kwargs) -> str:
        try:
            if not url.startswith("http"):
                url = "https://" + url
            cmd = [
                "wpscan", "--url", url,
                "--enumerate", enumerate,
                "--no-banner",
                "--format", "cli",
                "--max-threads", "5",
                "--request-timeout", "10",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            output = result.stdout or result.stderr or "No output"
            lines = output.split("\n")
            key_lines = [l for l in lines if any(k in l for k in ["[!]","[+]","[i]","CVE","VULNERABILITY","Username","Plugin","Theme","version"])]
            return f"=== WPScan: {url} ===\nKey findings:\n" + "\n".join(key_lines[:60])
        except subprocess.TimeoutExpired:
            return f"wpscan timed out for: {url}"
        except FileNotFoundError:
            return "Error: wpscan not installed."
        except Exception as e:
            return f"wpscan error: {e}"


class AmassSubdomainTool(Tool):
    name = "amass_subdomains"
    description = (
        "Passive subdomain enumeration using amass. "
        "Finds subdomains via certificate transparency, DNS databases, APIs. "
        "Very thorough passive recon — no direct target contact needed. "
        "Use this alongside theHarvester for maximum subdomain coverage."
    )
    parameters = {
        "domain": "Target domain (e.g. example.com — no http://)",
        "timeout": "Timeout in minutes (Default: 2)"
    }

    def execute(self, domain: str = None, target: str = None, url: str = None, timeout: str = "2", **kwargs) -> str:
        domain = domain or target or url or ""
        try:
            domain = domain.replace("https://","").replace("http://","").split("/")[0]
            cmd = ["amass", "enum", "-passive", "-d", domain, "-timeout", timeout]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=int(timeout)*60+60)
            output = result.stdout or result.stderr or "No subdomains found"
            subdomains = [l.strip() for l in output.split("\n") if l.strip() and domain in l]
            return f"=== Amass Subdomains: {domain} ===\nFound: {len(subdomains)}\n" + "\n".join(subdomains[:50])
        except subprocess.TimeoutExpired:
            return f"amass timed out for: {domain}"
        except FileNotFoundError:
            return "Error: amass not installed."
        except Exception as e:
            return f"amass error: {e}"


class DnsDigTool(Tool):
    name = "dns_lookup"
    description = (
        "Quick DNS lookup using dig/host. "
        "Finds: IP address (A record), mail servers (MX), nameservers (NS), "
        "SPF/DKIM records (TXT), reverse DNS (PTR). "
        "Fast, lightweight — use for quick target IP resolution and basic DNS info."
    )
    parameters = {
        "domain": "Domain to lookup (e.g. example.com)",
        "record_type": "DNS record type: A, MX, NS, TXT, AAAA, CNAME, ANY (Default: A)"
    }

    def execute(self, domain: str = None, target: str = None, url: str = None, record_type: str = "A", **kwargs) -> str:
        domain = domain or target or url or ""
        try:
            domain = domain.replace("https://","").replace("http://","").split("/")[0]
            cmd = ["dig", "+short", record_type, domain]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            output = result.stdout.strip() or "No records found"
            # Also get all records
            cmd2 = ["dig", "+noall", "+answer", record_type, domain]
            result2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=10)
            return f"=== DNS Lookup: {domain} ({record_type}) ===\nShort: {output}\nFull:\n{result2.stdout}"
        except Exception as e:
            return f"dig error: {e}"


class CurlHeadersTool(Tool):
    name = "curl_headers"
    description = (
        "Fetches HTTP response headers from a URL using curl. "
        "Reveals: server software + version, security headers (X-Frame-Options, CSP, HSTS), "
        "cookies with/without HttpOnly/Secure flags, redirect chains, "
        "and any API keys or tokens accidentally exposed in headers."
    )
    parameters = {
        "url": "Target URL (e.g. https://example.com/api/v1/)",
        "follow_redirects": "Follow redirects: true or false (Default: true)"
    }

    def execute(self, url: str, follow_redirects: str = "true", **kwargs) -> str:
        try:
            if not url.startswith("http"):
                url = "https://" + url
            cmd = ["curl", "-sI", "--max-time", "10", "--connect-timeout", "5"]
            if follow_redirects == "true":
                cmd.append("-L")
            cmd.append(url)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            output = result.stdout or result.stderr or "No response"
            return f"=== HTTP Headers: {url} ===\n{output}"
        except Exception as e:
            return f"curl error: {e}"
