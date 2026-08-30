from tools.base import Tool
import requests
import re

class IPInfoLookupTool(Tool):
    name = "ipinfo_lookup"
    description = "Fetches detailed information about an IP address using the ipinfo.io API."
    parameters = {"ip": "IP address to lookup"}

    def execute(self, ip: str = None, target: str = None, **kwargs) -> str:
        raw_input = ip or target or kwargs.get('ip') or kwargs.get('target') or ""
        if not raw_input:
            return "Error: No IP address or domain provided"

        # Clean URL prefixes and ports
        clean_target = raw_input.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip()

        # If domain, resolve to IP address
        import socket
        ip_pattern = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        if re.search(ip_pattern, clean_target):
            ip_address = clean_target
        else:
            try:
                ip_address = socket.gethostbyname(clean_target)
            except Exception as resolve_err:
                return f"Error: Could not resolve domain '{clean_target}' to IP address: {resolve_err}"

        try:
            # Make API request to ipinfo.io
            response = requests.get(f"https://ipinfo.io/{ip_address}/json", timeout=10)
            response.raise_for_status()
            data = response.json()
            return str(data)
        except requests.exceptions.RequestException as e:
            return f"Error: {str(e)}"