from tools.base import Tool
import requests

class WpJsonUsersTool(Tool):
    name = "wp_json_users"
    description = "Enumerates WordPress users via REST API."
    parameters = {"target": "Target WordPress site URL"}

    def execute(self, target: str = None, **kwargs) -> str:
        if not target:
            return "Error: Target URL is required"

        try:
            # Construct the REST API URL for users
            api_url = f"{target.rstrip('/')}/wp-json/wp/v2/users"

            # Make the GET request to the REST API
            response = requests.get(api_url, timeout=10)

            # Check if the request was successful
            if response.status_code == 200:
                # Return the JSON response
                return response.json()
            else:
                # Return the error message
                return f"Error: HTTP {response.status_code} - {response.text}"
        except requests.exceptions.RequestException as e:
            # Handle any request exceptions
            return f"Error: {str(e)}"