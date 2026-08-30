"""
Sublist3r - Fast Subdomain Enumeration
Requires: sublist3r (pip install sublist3r)
"""
import subprocess
from tools.base import Tool

class Sublist3rTool(Tool):
    name = "sublist3r_subdomains"
    description = "Enumerates subdomains using Sublist3r (passive sources: Google, Yahoo, Bing, etc.)"
    parameters = {
        "domain": "Target domain (e.g. example.com)",
        "threads": "Number of threads (default: 10)"
    }

    def execute(self, domain: str = None, target: str = None, threads: int = 10, **kwargs) -> str:
        domain = domain or target or ""
        domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
        if not domain:
            return "Error: Domain required."

        try:
            cmd = ["sublist3r", "-d", domain, "-t", str(threads)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
            output = result.stdout or result.stderr or ""
            subdomains = [line.strip() for line in output.split("\n") if domain in line and line.strip()]
            return f"=== Sublist3r: {domain} ===\nFound {len(subdomains)}:\n" + "\n".join(subdomains[:50])
        except FileNotFoundError:
            return "Error: 'sublist3r' not installed. Run: pip install sublist3r"
        except Exception as e:
            return f"Sublist3r error: {str(e)}"
