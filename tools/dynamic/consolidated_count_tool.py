from tools.base import Tool
import requests
import json

class ConsolidatedCountTool(Tool):
    name = "consolidated_count"
    description = "Consolidates and counts various security-related data points from a target system."
    parameters = {"target": "IP or hostname", "timeout": "Timeout in seconds"}

    def execute(self, target: str, timeout: int = 10, **kwargs) -> str:
        try:
            # Fetch security-related data from the target
            url = f"http://{target}/security-data"
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()

            # Process the data to provide a consolidated count
            data = response.json()
            consolidated_count = {
                "vulnerabilities": len(data.get("vulnerabilities", [])),
                "open_ports": len(data.get("open_ports", [])),
                "services": len(data.get("services", [])),
                "users": len(data.get("users", []))
            }

            return json.dumps(consolidated_count)
        except requests.exceptions.RequestException as e:
            return f"[ERROR] Request failed: {str(e)}"
        except json.JSONDecodeError as e:
            return f"[ERROR] Failed to decode JSON response: {str(e)}"
        except Exception as e:
            return f"[ERROR] An unexpected error occurred: {str(e)}"