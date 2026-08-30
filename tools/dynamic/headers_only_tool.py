from tools.base import Tool
import requests

class HeadersOnlyTool(Tool):
    name = "headers_only"
    description = "Fetches HTTP response headers from a target URL safely."
    parameters = {"target": "Target URL or IP address to inspect"}

    def execute(self, target: str = None, **kwargs) -> str:
        target_url = target or kwargs.get('url') or kwargs.get('domain') or kwargs.get('host') or "http://127.0.0.1"
        try:
            resp = requests.get(target_url, timeout=10, verify=False)
            return f"HTTP {resp.status_code}\nHeaders: {dict(resp.headers)}"
        except Exception as e:
            return f"[ERROR] Request failed: {str(e)}"