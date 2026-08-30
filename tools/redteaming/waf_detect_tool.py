"""
wafw00f — Web Application Firewall Detector
Critical step before any active scanning — tells you if a WAF exists.
If WAF detected: use evasion techniques. If no WAF: scan more aggressively.
"""
import subprocess
from tools.base import Tool

class WafDetectTool(Tool):
    name = "waf_detect"
    description = (
        "Detects Web Application Firewalls (WAF) on a target. "
        "Identifies 150+ WAFs: Cloudflare, AWS WAF, Imperva, Akamai, ModSecurity, etc. "
        "IMPORTANT: Run this before active scanning to know if you need evasion techniques."
    )
    parameters = {
        "url": "Target URL (e.g. https://example.com)"
    }

    def execute(self, url: str = None, target_url: str = None, target: str = None, domain: str = None, **kwargs) -> str:
        url = url or target_url or target or domain or ""
        try:
            if not url.startswith("http"):
                url = "https://" + url
            cmd = ["wafw00f", url, "-a"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            output = result.stdout or result.stderr or "No output"
            return f"=== WAF Detection: {url} ===\n{output}"
        except subprocess.TimeoutExpired:
            return f"wafw00f timed out for: {url}"
        except FileNotFoundError:
            return "Error: wafw00f not installed."
        except Exception as e:
            return f"wafw00f error: {e}"
