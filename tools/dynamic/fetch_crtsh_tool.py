from tools.base import Tool
import requests

class FetchCrtshTool(Tool):
    name = "fetch_crtsh"
    description = "Fetches SSL certificate information from crt.sh for a given domain."
    parameters = {"target": "Domain to query crt.sh for"}

    def execute(self, target: str = None, **kwargs) -> str:
        if not target:
            return "Error: No target domain provided"

        try:
            url = f"https://crt.sh/?q={target}&output=json"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as e:
            return f"Error: {str(e)}"