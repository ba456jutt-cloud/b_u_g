"""
Deterministic Scanning Engine (Stage 1 Core)
Executes deterministic, rule-based scanning without LLM token overhead.
Incorporates OSCP penetration testing cheat sheets and service-specific enumeration rules.
"""

import subprocess
import socket
import json
import os
import re
import shutil
import urllib3
import requests
from concurrent.futures import ThreadPoolExecutor

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Service Enumeration Rules derived from OSCP Guide Notes
OSCP_SERVICE_RULES = {
    "21": {
        "name": "FTP",
        "commands": [
            "ftp_anon_check"
        ]
    },
    "22": {
        "name": "SSH",
        "commands": [
            "ssh_banner_check"
        ]
    },
    "53": {
        "name": "DNS",
        "commands": [
            "dns_zone_transfer"
        ]
    },
    "80": {
        "name": "HTTP",
        "commands": [
            "web_recon"
        ]
    },
    "443": {
        "name": "HTTPS",
        "commands": [
            "web_recon",
            "ssl_check"
        ]
    },
    "139": {
        "name": "NetBIOS",
        "commands": [
            "smb_null_check"
        ]
    },
    "445": {
        "name": "SMB",
        "commands": [
            "smb_null_check"
        ]
    },
    "3306": {
        "name": "MySQL",
        "commands": [
            "mysql_info_check"
        ]
    }
}


class DeterministicScanningEngine:
    def __init__(self, target_url: str):
        self.raw_target = str(target_url).strip()
        match = re.search(r'https?://[^\s\'"\}]+|[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', self.raw_target)
        extracted = match.group(0) if match else self.raw_target
        self.clean_domain = extracted.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip()
        self.url = f"https://{self.clean_domain}"
        self.ip_address = ""
        self.open_ports = []
        self.services = {}
        self.enum_results = {}

    def run(self) -> dict:
        """Run complete Stage 1 deterministic scanning workflow."""
        results = {
            "target": self.raw_target,
            "domain": self.clean_domain,
            "url": self.url,
            "ip_address": "",
            "open_ports": [],
            "services": {},
            "enumeration": {}
        }

        # 1. Resolve IP
        self.ip_address = self._resolve_ip()
        results["ip_address"] = self.ip_address
        target_host = self.ip_address or self.clean_domain

        # 2. Fast Port Scan (Nmap / socket fallback)
        self.open_ports, self.services = self._scan_ports(target_host)
        results["open_ports"] = self.open_ports
        results["services"] = self.services

        # 3. Rule-based Service Specific Deep Enumeration (OSCP Rules)
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_port = {}
            for port in self.open_ports:
                port_str = str(port)
                if port_str in OSCP_SERVICE_RULES:
                    rule = OSCP_SERVICE_RULES[port_str]
                    future_to_port[executor.submit(self._enum_service, target_host, port_str, rule)] = port_str
                elif port in [8000, 8080, 8443, 8888, 3000]:
                    future_to_port[executor.submit(self._enum_web, target_host, port_str)] = port_str

            for future in future_to_port:
                port_str = future_to_port[future]
                try:
                    self.enum_results[port_str] = future.result()
                except Exception as e:
                    self.enum_results[port_str] = {"error": str(e)}

        results["enumeration"] = self.enum_results

        # 4. Save to /tmp/discovery_cache.json
        self._write_cache(results)
        return results

    def _resolve_ip(self) -> str:
        try:
            return socket.gethostbyname(self.clean_domain)
        except Exception:
            return ""

    def _scan_ports(self, host: str) -> tuple[list, dict]:
        open_ports = []
        services = {}

        if shutil.which("nmap"):
            try:
                # Use -sT (connect scan) for non-root users; -sS (SYN scan) needs root/CAP_NET_RAW
                scan_type = "-sS" if os.getuid() == 0 else "-sT"
                # Scan top-1000 ports for better coverage (top-100 misses 99.8% of ports)
                cmd = ["nmap", "-Pn", "-T4", scan_type, "--top-ports", "1000", "-sV", "--open", host]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
                stdout = res.stdout or ""

                # If filtered / blocked, try evasion with source port 53 (DNS)
                if "0 ports open" in stdout or "filtered" in stdout:
                    cmd_evade = [
                        "nmap", "-Pn", scan_type, "-g", "53",
                        "-p", "21,22,23,25,53,69,80,110,111,135,139,143,443,445,587,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,8888,27017",
                        "-sV", host
                    ]
                    res = subprocess.run(cmd_evade, capture_output=True, text=True, timeout=120)
                    stdout = res.stdout or ""

                for line in stdout.split("\n"):
                    match = re.search(r'^(\d+)/(tcp|udp)\s+open\s+([^\s]+)\s*(.*)', line.strip())
                    if match:
                        p = int(match.group(1))
                        srv = match.group(3)
                        ver = match.group(4)
                        open_ports.append(p)
                        services[str(p)] = {"service": srv, "version": ver}

            except Exception:
                pass

        # Fallback socket scan for common ports if Nmap fails or returns empty
        if not open_ports:
            common_ports = [21, 22, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 8000, 8080, 8443]
            for p in common_ports:
                try:
                    with socket.create_connection((host, p), timeout=1.5):
                        open_ports.append(p)
                        services[str(p)] = {"service": "unknown", "version": ""}
                except Exception:
                    pass

        return open_ports, services

    def _enum_service(self, host: str, port: str, rule: dict) -> dict:
        results = {"service_name": rule["name"], "findings": []}
        for cmd_type in rule["commands"]:
            if cmd_type == "ftp_anon_check":
                results["ftp_anonymous"] = self._check_ftp_anon(host)
            elif cmd_type == "ssh_banner_check":
                results["ssh_banner"] = self._check_ssh_banner(host, int(port))
            elif cmd_type == "dns_zone_transfer":
                results["dns_axfr"] = self._check_dns_axfr(self.clean_domain)
            elif cmd_type == "web_recon":
                results["web"] = self._enum_web(host, port)
            elif cmd_type == "ssl_check":
                results["ssl"] = self._check_ssl(self.clean_domain)
            elif cmd_type == "smb_null_check":
                results["smb"] = self._check_smb(host)
            elif cmd_type == "mysql_info_check":
                results["mysql"] = self._check_mysql(host)
        return results

    def _check_ftp_anon(self, host: str) -> str:
        import ftplib
        try:
            ftp = ftplib.FTP(timeout=5)
            ftp.connect(host, 21)
            res = ftp.login('anonymous', 'anonymous@')
            ftp.quit()
            return f"✅ Anonymous FTP Login SUCCESSFUL ({res})"
        except Exception as e:
            return f"Anonymous FTP disabled ({str(e)})"

    def _check_ssh_banner(self, host: str, port: int = 22) -> str:
        try:
            with socket.create_connection((host, port), timeout=3) as sock:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner or "No banner"
        except Exception as e:
            return f"Error grabbing SSH banner: {e}"

    def _check_dns_axfr(self, domain: str) -> str:
        try:
            res = subprocess.run(["dig", "axfr", domain, f"@{domain}"], capture_output=True, text=True, timeout=10)
            if "TRANSFER FAILED" in res.stdout or not res.stdout.strip():
                return "Zone transfer denied (Secure)"
            return res.stdout[:1000]
        except Exception as e:
            return f"AXFR check error: {e}"

    def _enum_web(self, host: str, port: str) -> dict:
        scheme = "https" if port == "443" or port == "8443" else "http"
        target_url = f"{scheme}://{self.clean_domain}:{port}" if port not in ["80", "443"] else f"{scheme}://{self.clean_domain}"
        
        data = {"url": target_url}
        try:
            # Realistic User-Agent to avoid WAF blocking (SecurityBot/1.0 triggers WAF blocklists)
            _UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/124.0.0.0 Safari/537.36")
            resp = requests.get(target_url, timeout=8, verify=False, allow_redirects=True,
                                headers={"User-Agent": _UA})
            data["status_code"] = resp.status_code
            data["server"] = resp.headers.get("Server", "Unknown")
            data["x_powered_by"] = resp.headers.get("X-Powered-By", "Not Disclosed")
            
            # Simple signature detection (CMS / Tech)
            body = resp.text.lower()[:5000]
            techs = []
            if "wp-content" in body or "wp-includes" in body:
                techs.append("WordPress")
            if "elementor" in body:
                techs.append("Elementor")
            if "jquery" in body:
                techs.append("jQuery")
            data["detected_technologies"] = techs

        except Exception as e:
            data["error"] = str(e)
        return data

    def _check_ssl(self, domain: str) -> dict:
        try:
            from tools.redteaming.ssl_tool import SSLCheckerTool
            tool = SSLCheckerTool()
            res = tool.execute(host=domain)
            return {"report": str(res)[:600]}
        except Exception as e:
            return {"error": str(e)}

    def _check_smb(self, host: str) -> str:
        if shutil.which("smbclient"):
            try:
                res = subprocess.run(["smbclient", "-L", f"//{host}", "-N"], capture_output=True, text=True, timeout=10)
                if "Sharename" in res.stdout:
                    return f"✅ SMB Null Session Allowed:\n{res.stdout[:500]}"
                return "SMB Null Session denied"
            except Exception as e:
                return f"SMB check error: {e}"
        return "smbclient CLI tool not installed"

    def _check_mysql(self, host: str) -> str:
        try:
            with socket.create_connection((host, 3306), timeout=3) as sock:
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                clean_banner = re.sub(r'[^\x20-\x7E]', '', banner)
                return f"MySQL Port 3306 Open. Banner: {clean_banner[:100]}"
        except Exception as e:
            return f"MySQL check error: {e}"

    def _write_cache(self, data: dict, task_id: str = "global"):
        """Write Stage 1 discovery results to a task-scoped cache file.
        Using task_id prevents concurrent scans from overwriting each other's cache.
        Also writes to the legacy shared path for backward compatibility.
        """
        # Task-scoped cache path (FIXED: was shared /tmp/discovery_cache.json)
        safe_task_id = re.sub(r'[^a-zA-Z0-9_-]', '_', str(task_id))[:40]
        task_cache_path = f"/tmp/discovery_cache_{safe_task_id}.json"
        # Also update the legacy shared path for tools that haven't migrated yet
        legacy_cache_path = "/tmp/discovery_cache.json"

        payload = {
            "task_id": task_id,
            "ip": data.get("ip_address"),
            "domain": data.get("domain"),
            "url": data.get("url"),
            "open_ports": data.get("open_ports"),
            "services": data.get("services"),
            "enumeration": data.get("enumeration"),
            "stage1_complete": True
        }

        for cache_path in [task_cache_path, legacy_cache_path]:
            try:
                existing = {}
                if os.path.exists(cache_path):
                    with open(cache_path, "r") as f:
                        existing = json.load(f)
                existing.update(payload)
                with open(cache_path, "w") as f:
                    json.dump(existing, f, indent=2)
            except Exception as e:
                print(f"[DeterministicEngine] Error writing cache {cache_path}: {e}")
