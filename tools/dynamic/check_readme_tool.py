from tools.base import Tool
import requests

class CheckReadmeTool(Tool):
    name = "check_readme"
    description = "Fetches and analyzes the README content from a target URL."
    parameters = {"url": "Target URL to fetch README from"}

    def execute(self, url: str = None, target: str = None, **kwargs) -> str:
        target_url = url or target or kwargs.get('url') or "https://scholarhub.online/readme.html"
        try:
            resp = requests.get(target_url, timeout=10, verify=False)
            if resp.status_code == 200:
                return resp.text
            else:
                return f"Error: Failed to fetch README. HTTP Status Code: {resp.status_code}"
        except requests.exceptions.RequestException as e:
            return f"Error: Request failed: {str(e)}"
        except Exception as e:
            return f"Error: An unexpected error occurred: {str(e)}"