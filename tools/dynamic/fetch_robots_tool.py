from tools.base import Tool
import requests

class FetchRobotsTool(Tool):
    name = "fetch_robots"
    description = "Fetches the robots.txt file from a target URL."
    parameters = {"url": "Target URL to fetch robots.txt from"}

    def execute(self, url: str = None, target: str = None, **kwargs) -> str:
        target_url = url or target or kwargs.get('domain') or kwargs.get('host') or "http://127.0.0.1"
        robots_url = f"{target_url.rstrip('/')}/robots.txt"
        try:
            resp = requests.get(robots_url, timeout=10, verify=False)
            resp.raise_for_status()
            return resp.text
        except requests.exceptions.RequestException as e:
            return f"[ERROR] Failed to fetch robots.txt: {str(e)}"