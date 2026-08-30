"""
dnsrecon — DNS Enumeration & Zone Transfer Tool
Finds: subdomains via zone transfer, DNS records (A, MX, TXT, NS, SRV, SOA).
Zone transfer misconfiguration = massive info leak (all subdomains exposed).
"""
import subprocess
from tools.base import Tool

class DnsReconTool(Tool):
    name = "dns_recon"
    description = (
        "Performs comprehensive DNS enumeration on a target domain. "
        "Checks for: DNS zone transfer (misconfiguration that leaks ALL subdomains), "
        "A/MX/NS/TXT/SRV records, reverse DNS, DNS cache snooping. "
        "Zone transfer = critical finding if enabled."
    )
    parameters = {
        "domain": "Target domain (e.g. example.com — no http://)",
        "mode": "Scan mode: 'std' (standard records), 'axfr' (zone transfer only), 'all' (everything). Default: std"
    }

    def execute(self, domain: str, mode: str = "std", **kwargs) -> str:
        try:
            domain = domain.replace("https://","").replace("http://","").split("/")[0]
            if mode == "axfr":
                cmd = ["dnsrecon", "-d", domain, "-t", "axfr"]
            elif mode == "all":
                cmd = ["dnsrecon", "-d", domain, "-t", "std,axfr,brt", "--lifetime", "3"]
            else:
                cmd = ["dnsrecon", "-d", domain, "-t", "std"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            output = result.stdout or result.stderr or "No output"
            return f"=== DNS Recon: {domain} (mode={mode}) ===\n{output}"
        except subprocess.TimeoutExpired:
            return f"dnsrecon timed out for: {domain}"
        except FileNotFoundError:
            return "Error: dnsrecon not installed."
        except Exception as e:
            return f"dnsrecon error: {e}"
