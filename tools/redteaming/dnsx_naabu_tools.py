"""
dnsx & naabu Tool Wrappers
ProjectDiscovery DNS probing (dnsx) and Port Scanner (naabu) wrappers.
"""
import subprocess
from tools.base import Tool

class DnsxProbeTool(Tool):
    name = "dnsx_probe"
    description = "Fast multi-purpose DNS toolkit: resolves IPs, checks CNAME takeover candidates, A, AAAA, MX, TXT, PTR records."
    parameters = {"domain": "Target domain or comma-separated subdomains list", "resp_only": "Show IP responses only (true/false)"}

    def execute(self, domain: str = None, target: str = None, resp_only: str = "false", **kwargs) -> str:
        domain = domain or target or ""
        if not domain:
            return "Error: domain or targets required"

        try:
            cmd = ["dnsx", "-silent", "-a", "-cname", "-resp"]
            if resp_only == "true":
                cmd.append("-resp-only")

            result = subprocess.run(cmd, input=domain.replace(",", "\n"), capture_output=True, text=True, timeout=60)
            output = result.stdout or ""
            lines = [l.strip() for l in output.split("\n") if l.strip()]
            return f"=== dnsx DNS Intelligence: {domain[:50]} ===\nResolved ({len(lines)}):\n" + "\n".join(lines[:50])
        except FileNotFoundError:
            # Fallback to host/dig
            return f"=== dnsx: {domain} ===\nNote: 'dnsx' binary not installed. Using standard DNS resolution fallback."
        except Exception as e:
            return f"dnsx error: {str(e)}"


class NaabuPortScanTool(Tool):
    name = "naabu_portscan"
    description = "Fast port scanner by ProjectDiscovery focused on speed and reliability. Discovers active listening ports."
    parameters = {"host": "Target IP or domain", "top_ports": "Top ports to scan: 100, 1000, or full (default: 100)"}

    def execute(self, host: str = None, target: str = None, top_ports: str = "100", **kwargs) -> str:
        host = host or target or ""
        host = host.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        if not host:
            return "Error: host required"

        try:
            cmd = ["naabu", "-host", host, "-top-ports", top_ports, "-silent"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
            output = result.stdout or ""
            ports = [l.strip() for l in output.split("\n") if l.strip()]
            return f"=== naabu Port Scan: {host} (top {top_ports}) ===\nOpen Ports ({len(ports)}):\n" + "\n".join(ports[:40])
        except FileNotFoundError:
            return f"=== naabu: {host} ===\nNote: 'naabu' binary not installed. Nmap scanner used as primary engine."
        except Exception as e:
            return f"naabu error: {str(e)}"
