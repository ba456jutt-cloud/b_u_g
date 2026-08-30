from tools.base import Tool
import requests

class UsersApiTool(Tool):
    name = "users_api"
    description = "Fetches user data from a WordPress REST API endpoint."
    parameters = {"url": "Target WordPress REST API URL"}

    def execute(self, url: str = None, target: str = None, **kwargs) -> str:
        target_url = url or target or kwargs.get('url') or "https://scholarhub.online/wp-json/wp/v2/users"
        try:
            resp = requests.get(target_url, timeout=10, verify=False)
            if resp.status_code == 200:
                return resp.json()
            else:
                return f"Error: HTTP {resp.status_code} - {resp.text}"
        except requests.exceptions.RequestException as e:
            return f"[ERROR] Request failed: {str(e)}"