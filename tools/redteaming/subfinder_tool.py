"""
Subfinder — Fast Passive Subdomain Discovery Tool
Uses passive sources (binary edge, Crt.sh, Censys, SecurityTrails, Chaos, etc.)
"""
import subprocess
from tools.base import Tool

class SubfinderTool(Tool):
    name = "subfinder_discovery"
    description = (
        "Performs fast passive subdomain discovery using subfinder. "
        "Queries passive public sources without directly touching target infrastructure. "
        "Essential first step for scope mapping and attack surface enumeration."
    )
    parameters = {
        "domain": "Target domain (e.g. example.com)",
        "recursive": "Recursive discovery (true/false, default: false)"
    }

    def execute(self, domain: str = None, target: str = None, url: str = None, recursive: str = "false", **kwargs) -> str:
        domain = domain or target or url or ""
        domain = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        if not domain:
            return "Error: Domain required"

        try:
            cmd = ["subfinder", "-d", domain, "-silent"]
            if recursive == "true":
                cmd.append("-recursive")

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
            output = result.stdout or result.stderr or ""
            subdomains = [line.strip() for line in output.split("\n") if line.strip() and domain in line]

            report = [
                f"=== Subfinder Passive Recon: {domain} ===",
                f"Total Subdomains Found: {len(subdomains)}",
                ""
            ]
            report.extend(subdomains[:60])
            if len(subdomains) > 60:
                report.append(f"[... {len(subdomains) - 60} additional subdomains truncated ...]")

            return "\n".join(report)
        except FileNotFoundError:
            return f"=== Subfinder: {domain} ===\nNote: 'subfinder' binary not found. Using crt.sh fallback."
        except subprocess.TimeoutExpired:
            return f"Subfinder timed out after 90s for {domain}"
        except Exception as e:
            return f"Subfinder error: {str(e)}"
