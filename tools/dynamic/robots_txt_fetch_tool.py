from tools.base import Tool
import requests

class RobotsTxtFetchTool(Tool):
    name = "robots_txt_fetch"
    description = "Fetches and analyzes the robots.txt file from a target web server."
    parameters = {"url": "Target URL to fetch robots.txt from"}

    def execute(self, url: str = None, target: str = None, **kwargs) -> str:
        target_url = url or target or kwargs.get('domain') or kwargs.get('host') or "http://127.0.0.1"
        robots_url = f"{target_url.rstrip('/')}/robots.txt"
        try:
            resp = requests.get(robots_url, timeout=10, verify=False)
            if resp.status_code == 200:
                return f"Robots.txt content:\n{resp.text}"
            else:
                return f"Error: Received HTTP {resp.status_code} status code"
        except requests.exceptions.RequestException as e:
            return f"[ERROR] Request failed: {str(e)}"