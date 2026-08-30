from tools.base import Tool
import requests

class RobotsTxtTool(Tool):
    name = "robots_txt"
    description = "Fetches and analyzes the robots.txt file from a target URL."
    parameters = {"url": "Target URL to fetch robots.txt from"}

    def execute(self, url: str = None, target: str = None, **kwargs) -> str:
        target_url = url or target or kwargs.get('domain') or kwargs.get('host') or "http://127.0.0.1"
        robots_url = f"{target_url.rstrip('/')}/robots.txt"
        try:
            resp = requests.get(robots_url, timeout=10, verify=False)
            return {"url": robots_url, "status": resp.status_code, "content": resp.text}
        except Exception as e:
            return f"[ERROR] Request failed: {str(e)}"