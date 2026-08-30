"""
Assetfinder & Findomain Tool Wrappers
Fast passive domain discovery tools popular in bug bounty workflows.
"""
import subprocess
from tools.base import Tool

class AssetfinderTool(Tool):
    name = "assetfinder_discovery"
    description = "Finds subdomains and related domains using assetfinder passive sources."
    parameters = {"domain": "Target domain (e.g. example.com)"}

    def execute(self, domain: str = None, target: str = None, **kwargs) -> str:
        domain = domain or target or ""
        domain = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        if not domain:
            return "Error: domain required"

        try:
            cmd = ["assetfinder", "--subs-only", domain]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            output = result.stdout or ""
            subs = [l.strip() for l in output.split("\n") if l.strip() and domain in l]
            return f"=== Assetfinder: {domain} ===\nFound ({len(subs)}):\n" + "\n".join(subs[:50])
        except FileNotFoundError:
            return f"=== Assetfinder: {domain} ===\nNote: 'assetfinder' binary not installed."
        except Exception as e:
            return f"Assetfinder error: {str(e)}"


class FindomainTool(Tool):
    name = "findomain_discovery"
    description = "Fast domain discovery tool using Findomain API and passive search."
    parameters = {"domain": "Target domain (e.g. example.com)"}

    def execute(self, domain: str = None, target: str = None, **kwargs) -> str:
        domain = domain or target or ""
        domain = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        if not domain:
            return "Error: domain required"

        try:
            cmd = ["findomain", "-t", domain, "-q"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            output = result.stdout or ""
            subs = [l.strip() for l in output.split("\n") if l.strip() and domain in l]
            return f"=== Findomain: {domain} ===\nFound ({len(subs)}):\n" + "\n".join(subs[:50])
        except FileNotFoundError:
            return f"=== Findomain: {domain} ===\nNote: 'findomain' binary not installed."
        except Exception as e:
            return f"Findomain error: {str(e)}"
