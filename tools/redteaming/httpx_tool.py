"""
httpx — Fast HTTP Probing & Technology Fingerprinting
Essential bug bounty tool by ProjectDiscovery
"""
import subprocess
import json
from tools.base import Tool

class HttpxProbeTool(Tool):
    name = "httpx_probe"
    description = "Uses httpx to rapidly probe a list of subdomains or URLs for live HTTP/HTTPS services."
    parameters = {
        "targets": "Single URL or comma-separated list of domains/subdomains to probe",
        "options": "full or fast"
    }

    def execute(self, targets: str = None, target: str = None, url: str = None,
                domain: str = None, host: str = None, target_url: str = None,
                options: str = "full", **kwargs) -> str:
        # Normalize: pick the first non-None from various aliases
        if targets is None:
            targets = target or url or domain or host or target_url or ""
        if isinstance(targets, list):
            targets = ",".join(targets)
        targets = str(targets).strip()
        if not targets:
            return "Error: No valid targets provided."

        target_list = [t.strip() for t in targets.replace("\n", ",").split(",") if t.strip()]
        if not target_list:
            return "Error: No valid targets provided."

        results = []
        live = []
        login_pages = []

        for target_item in target_list[:20]:
            if not target_item.startswith("http"):
                target_http  = f"http://{target_item}"
                target_https = f"https://{target_item}"
            else:
                target_http = target_item
                target_https = target_item

            # Use curl to probe — available everywhere
            cmd = ["curl", "-sI", "-L", "--max-time", "8",
                   "--connect-timeout", "5",
                   "-w", r"\nSTATUS:%{http_code} SIZE:%{size_download} URL:%{url_effective}",
                   target_http]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
            output = result.stdout or ""

            status = ""
            final_url = ""
            for line in output.split("\n"):
                if line.startswith("STATUS:"):
                    parts = line.split()
                    status = parts[0].replace("STATUS:","")
                    final_url = parts[2].replace("URL:","") if len(parts) > 2 else target_http

            server = ""
            for line in output.split("\n"):
                if line.lower().startswith("server:"):
                    server = line.split(":",1)[1].strip()

            if status and status != "000":
                info = f"[{status}] {final_url} | Server: {server or 'unknown'}"
                results.append(info)
                live.append(info)
                if any(k in final_url.lower() for k in ["login","admin","dashboard","portal"]):
                    login_pages.append(info)

        report = [
            "=== HTTP Probe Results ===",
            f"Targets probed: {len(target_list)}  |  Live: {len(live)}",
            "",
            "--- Live Services ---",
        ]
        report.extend(live[:50] or ["No live services found."])

        if login_pages:
            report.append(f"\n🎯 INTERESTING — Login/Admin pages ({len(login_pages)}):")
            report.extend(login_pages)

        return "\n".join(report)

