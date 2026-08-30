from tools.base import Tool
import requests
import json

class CrtShSearchTool(Tool):
    name = "crt_sh_search"
    description = "Searches crt.sh for SSL certificates associated with a target domain."
    parameters = {"target": "Domain to search for SSL certificates"}

    def execute(self, target: str = None, url: str = None, **kwargs) -> str:
        raw_target = target or url or kwargs.get('domain') or kwargs.get('host') or ""
        if not raw_target:
            return "Error: Target domain not provided"

        # Clean URL prefixes, slashes, ports
        clean_domain = raw_target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip()
        if not clean_domain:
            return "Error: Invalid target domain"

        try:
            # Make a request to the crt.sh API
            response = requests.get(f"https://crt.sh/?q=%25.{clean_domain}&output=json", timeout=15)
            response.raise_for_status()

            # Parse the JSON response
            certificates = response.json()

            # Extract relevant information from the certificates
            results = []
            for cert in certificates:
                results.append({
                    "common_name": cert.get("common_name"),
                    "issuer_name": cert.get("issuer_name"),
                    "not_before": cert.get("not_before"),
                    "not_after": cert.get("not_after"),
                    "serial_number": cert.get("serial_number")
                })

            return json.dumps(results, indent=2)
        except requests.exceptions.RequestException as e:
            return f"Error: {str(e)}"
        except json.JSONDecodeError as e:
            return f"Error: Failed to parse JSON response - {str(e)}"