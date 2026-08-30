from tools.base import Tool
import requests

class CheckLicenseTool(Tool):
    name = "check_license"
    description = "Fetches and verifies the license file from a specified URL."
    parameters = {"url": "URL of the license file to fetch"}

    def execute(self, url: str = None, target: str = None, **kwargs) -> str:
        target_url = url or target or kwargs.get('url') or "https://scholarhub.online/license.txt"
        try:
            resp = requests.get(target_url, timeout=10, verify=False)
            if resp.status_code == 200:
                return resp.text
            else:
                return f"Error: Failed to fetch license file. HTTP Status Code: {resp.status_code}"
        except requests.exceptions.RequestException as e:
            return f"Error: Failed to fetch license file. Exception: {str(e)}"