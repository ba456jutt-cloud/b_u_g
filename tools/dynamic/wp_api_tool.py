from tools.base import Tool
import requests

class WpApiTool(Tool):
    name = "wp_api"
    description = "Interacts with WordPress REST API endpoints to gather information about the target."
    parameters = {
        "url": "Base URL of the WordPress site",
        "status": "Expected HTTP status code for successful requests",
        "endpoints": "List of WordPress API endpoints to check"
    }

    def execute(self, url: str = None, status: int = 200, endpoints: list = None, **kwargs) -> str:
        if not url:
            return "Error: URL parameter is required."

        if not endpoints:
            endpoints = ['wp/v2/users', 'wp/v2/posts', 'wp/v2/pages', 'wp/v2/media', 'wp/v2/settings', 'rest_route']

        results = {}

        for endpoint in endpoints:
            try:
                response = requests.get(f"{url}{endpoint}", timeout=10)
                if response.status_code == status:
                    results[endpoint] = response.json()
                else:
                    results[endpoint] = f"Error: Unexpected status code {response.status_code}"
            except requests.exceptions.RequestException as e:
                results[endpoint] = f"Error: {str(e)}"

        return str(results)