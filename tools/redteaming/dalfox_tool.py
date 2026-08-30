"""
Dalfox - XSS Scanner and Payload Generator
Requires: dalfox (go install github.com/hahwul/dalfox/v2@latest)
"""
import subprocess
from tools.base import Tool

class DalfoxTool(Tool):
    name = "dalfox_xss"
    description = "Scans for reflected and stored XSS vulnerabilities using Dalfox."
    parameters = {
        "url": "Target URL (e.g. https://example.com/page?param=test)",
        "method": "GET or POST (default: GET)",
        "cookie": "Cookie string (optional)"
    }

    def execute(self, url: str = None, target: str = None, method: str = "GET", cookie: str = None, **kwargs) -> str:
        url = url or target or ""
        if not url:
            return "Error: URL required."

        try:
            cmd = ["dalfox", "url", url, "--method", method, "--skip-bav"]
            if cookie:
                cmd.extend(["--cookie", cookie])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
            output = result.stdout or result.stderr or ""
            # Extract findings
            findings = [l for l in output.split("\n") if "[POC]" in l or "[V]" in l or "[WARN]" in l]
            return f"=== Dalfox XSS Scan: {url} ===\n" + "\n".join(findings[:40])
        except FileNotFoundError:
            return "Error: 'dalfox' not installed. Install: go install github.com/hahwul/dalfox/v2@latest"
        except Exception as e:
            return f"Dalfox error: {str(e)}"
