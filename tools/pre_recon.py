"""
Automated Pre-Recon Engine
Fires instantly before Step 1 to gather foundational OSINT & infrastructure data.
Passes clean consolidated findings directly into MasterAgent pipeline context.
"""

import socket
import json
import requests
import urllib3
import re
from concurrent.futures import ThreadPoolExecutor

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class PreReconEngine:
    def __init__(self, target_url: str):
        self.raw_target = str(target_url).strip()
        # Regex extract actual URL/domain from task string
        match = re.search(r'https?://[^\s\'"\}]+|[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', self.raw_target)
        extracted = match.group(0) if match else self.raw_target
        self.clean_domain = extracted.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip()
        self.url = f"https://{self.clean_domain}"
        self.ip_address = ""
        self.findings = {}

    def run_all() -> str:
        pass

    def run(self) -> dict:
        results = {}
        with ThreadPoolExecutor(max_workers=6) as executor:
            future_ip = executor.submit(self._resolve_ip)
            future_dns = executor.submit(self._get_dns_records)
            future_ssl = executor.submit(self._get_ssl_info)
            future_headers = executor.submit(self._get_headers)
            future_robots = executor.submit(self._get_robots_and_sitemap)
            future_whois = executor.submit(self._get_whois)

            self.ip_address = future_ip.result()
            results["ip_address"] = self.ip_address
            results["domain"] = self.clean_domain
            results["url"] = self.url
            results["dns_records"] = future_dns.result()
            results["ssl_info"] = future_ssl.result()
            results["http_headers"] = future_headers.result()
            results["robots_and_sitemap"] = future_robots.result()
            results["whois"] = future_whois.result()

            if self.ip_address:
                results["ip_geo"] = self._get_ip_info(self.ip_address)

        self.findings = results
        return results

    def get_summary_text(self) -> str:
        data = self.run()
        summary = [
            f"=== AUTOMATED PRE-RECON INTELLIGENCE REPORT ===",
            f"Target URL: {data.get('url')}",
            f"Domain: {data.get('domain')}",
            f"Resolved IP: {data.get('ip_address', 'Unknown')}",
        ]
        
        geo = data.get("ip_geo", {})
        if isinstance(geo, dict) and geo.get("org"):
            summary.append(f"ASN / ISP: {geo.get('org')} ({geo.get('city')}, {geo.get('country')})")

        dns = data.get("dns_records", {})
        if isinstance(dns, dict):
            summary.append("\n[DNS RECORDS]")
            summary.append(f"A Record: {dns.get('A', [])}")
            summary.append(f"MX Records: {dns.get('MX', [])}")
            summary.append(f"NS Servers: {dns.get('NS', [])}")
            summary.append(f"TXT Records: {dns.get('TXT', [])}")
            summary.append(f"SOA Record: {dns.get('SOA', 'None')}")

        hdrs = data.get("http_headers", {})
        if isinstance(hdrs, dict):
            summary.append("\n[HTTP STACK & SECURITY HEADERS]")
            summary.append(f"Status: {hdrs.get('status')}")
            summary.append(f"Server: {hdrs.get('server', 'Hidden/LiteSpeed')}")
            summary.append(f"X-Powered-By: {hdrs.get('x-powered-by', 'Not Disclosed')}")
            summary.append(f"Missing Headers: {hdrs.get('missing_headers', [])}")

        ssl = data.get("ssl_info", {})
        if isinstance(ssl, dict):
            summary.append("\n[SSL/TLS CERTIFICATE]")
            summary.append(f"Issuer: {ssl.get('issuer', 'Unknown')}")
            summary.append(f"Valid Until: {ssl.get('valid_until', 'Unknown')}")

        who = data.get("whois", {})
        if isinstance(who, dict) and who.get("registrar"):
            summary.append("\n[WHOIS DATA]")
            summary.append(f"Registrar: {who.get('registrar')}")
            summary.append(f"Created: {who.get('creation_date')}")

        robots = data.get("robots_and_sitemap", {})
        if isinstance(robots, dict):
            summary.append("\n[ROBOTS & SITEMAP]")
            summary.append(f"Robots.txt: {robots.get('robots_status')}")
            summary.append(f"Sitemap: {robots.get('sitemap_url')}")

        summary.append("================================================\n")
        return "\n".join(summary)

    def _resolve_ip(self) -> str:
        try:
            return socket.gethostbyname(self.clean_domain)
        except Exception:
            return ""

    def _get_dns_records(self) -> dict:
        records = {"A": [], "MX": [], "NS": [], "TXT": [], "SOA": "None"}
        import subprocess
        try:
            # dig A
            res = subprocess.run(["dig", "+short", "A", self.clean_domain], capture_output=True, text=True, timeout=5)
            records["A"] = [line.strip() for line in res.stdout.split("\n") if line.strip()]
            # dig MX
            res = subprocess.run(["dig", "+short", "MX", self.clean_domain], capture_output=True, text=True, timeout=5)
            records["MX"] = [line.strip() for line in res.stdout.split("\n") if line.strip()]
            # dig NS
            res = subprocess.run(["dig", "+short", "NS", self.clean_domain], capture_output=True, text=True, timeout=5)
            records["NS"] = [line.strip() for line in res.stdout.split("\n") if line.strip()]
            # dig TXT
            res = subprocess.run(["dig", "+short", "TXT", self.clean_domain], capture_output=True, text=True, timeout=5)
            records["TXT"] = [line.strip() for line in res.stdout.split("\n") if line.strip()]
            # dig SOA
            res = subprocess.run(["dig", "+short", "SOA", self.clean_domain], capture_output=True, text=True, timeout=5)
            records["SOA"] = res.stdout.strip() or "None"
        except Exception:
            pass
        return records

    def _get_ssl_info(self) -> dict:
        info = {}
        try:
            from tools.redteaming.ssl_tool import SSLCheckerTool
            tool = SSLCheckerTool()
            res = tool.execute(host=self.clean_domain)
            info["raw"] = res[:500]
            for line in str(res).split("\n"):
                if "Issuer:" in line:
                    info["issuer"] = line.split("Issuer:")[-1].strip()
                if "Valid Until:" in line:
                    info["valid_until"] = line.split("Valid Until:")[-1].strip()
        except Exception as e:
            info["error"] = str(e)
        return info

    def _get_headers(self) -> dict:
        res = {}
        try:
            resp = requests.get(self.url, timeout=10, verify=False, allow_redirects=True,
                                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityBot/1.0"})
            res["status"] = resp.status_code
            res["server"] = resp.headers.get("Server", "Undisclosed")
            res["x-powered-by"] = resp.headers.get("X-Powered-By", "Undisclosed")

            expected_sec = ["Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options", "Content-Security-Policy", "Referrer-Policy"]
            missing = [h for h in expected_sec if h.lower() not in {k.lower() for k in resp.headers.keys()}]
            res["missing_headers"] = missing
        except Exception as e:
            res["error"] = str(e)
        return res

    def _get_robots_and_sitemap(self) -> dict:
        res = {"robots_status": "Missing", "sitemap_url": "None"}
        try:
            r = requests.get(f"{self.url}/robots.txt", timeout=5, verify=False)
            if r.status_code == 200:
                res["robots_status"] = "Found (200 OK)"
                matches = re.findall(r'Sitemap:\s*(https?://[^\s]+)', r.text, re.IGNORECASE)
                if matches:
                    res["sitemap_url"] = matches[0]
        except Exception:
            pass
        return res

    def _get_ip_info(self, ip: str) -> dict:
        try:
            r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        return {}

    def _get_whois(self) -> dict:
        try:
            import whois
            w = whois.whois(self.clean_domain)
            return {
                "registrar": str(w.get("registrar", "")),
                "creation_date": str(w.get("creation_date", "")),
                "expiration_date": str(w.get("expiration_date", "")),
            }
        except Exception as e:
            return {"error": str(e)}
