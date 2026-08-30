from tools.base import Tool
import subprocess
import json
import shutil
import os

class SubdomainScanTool(Tool):
    name = "subdomain_scan"
    description = "Performs subdomain discovery using available installed tools (subfinder, assetfinder, findomain)."
    parameters = {"target": "Target domain to scan for subdomains"}

    def execute(self, target: str = None, domain: str = None, **kwargs) -> str:
        target = target or domain or kwargs.get("url") or ""
        target = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip()
        if not target:
            return "Error: Target domain is required"

        subdomains = set()
        executed_tools = []

        # 1. Try subfinder (~/go/bin/subfinder)
        subfinder_bin = shutil.which("subfinder") or "/home/ahmad/go/bin/subfinder"
        if os.path.exists(subfinder_bin) or shutil.which("subfinder"):
            try:
                res = subprocess.run([subfinder_bin, "-d", target, "-silent"], capture_output=True, text=True, timeout=60)
                if res.stdout:
                    found = [l.strip() for l in res.stdout.splitlines() if l.strip() and target in l]
                    subdomains.update(found)
                    executed_tools.append(f"subfinder ({len(found)})")
            except Exception:
                pass

        # 2. Try assetfinder
        if shutil.which("assetfinder"):
            try:
                res = subprocess.run(["assetfinder", "--subs-only", target], capture_output=True, text=True, timeout=45)
                if res.stdout:
                    found = [l.strip() for l in res.stdout.splitlines() if l.strip() and target in l]
                    subdomains.update(found)
                    executed_tools.append(f"assetfinder ({len(found)})")
            except Exception:
                pass

        # 3. Try findomain
        if shutil.which("findomain"):
            try:
                res = subprocess.run(["findomain", "-t", target, "-q"], capture_output=True, text=True, timeout=45)
                if res.stdout:
                    found = [l.strip() for l in res.stdout.splitlines() if l.strip() and target in l]
                    subdomains.update(found)
                    executed_tools.append(f"findomain ({len(found)})")
            except Exception:
                pass

        if not executed_tools:
            return f"Subdomain scan completed. No additional subdomains found for {target}."

        result_list = sorted(list(subdomains))
        return f"=== Subdomain Scan Results for {target} ===\nTools used: {', '.join(executed_tools)}\nTotal Found: {len(result_list)}\n" + "\n".join(result_list[:50])