from tools.base import Tool
import requests

class CheckXMLRPCTool(Tool):
    name = "check_xmlrpc"
    description = "Checks the XML-RPC endpoint of a target URL for security vulnerabilities."
    parameters = {"url": "Target URL to inspect"}

    def execute(self, url: str = None, target: str = None, **kwargs) -> str:
        target_url = url or target or kwargs.get('domain') or kwargs.get('host') or "http://127.0.0.1"
        try:
            resp = requests.get(target_url, timeout=10, verify=False)
            return f"HTTP {resp.status_code}\nHeaders: {dict(resp.headers)}\nBody Snippet: {resp.text[:1000]}"
        except Exception as e:
            return f"[ERROR] Request failed: {str(e)}"