from tools.base import Tool
import socket

class DnsALookupTool(Tool):
    name = "dns_a"
    description = "Performs a DNS A record lookup to resolve a domain name to an IP address."
    parameters = {"target": "Domain name to resolve"}

    def execute(self, target: str, **kwargs) -> str:
        try:
            # Perform DNS A record lookup with timeout
            ip_address = socket.gethostbyname(target)
            return f"DNS A record lookup successful. {target} resolves to {ip_address}"
        except socket.gaierror as e:
            return f"[ERROR] DNS lookup failed: {str(e)}"
        except socket.timeout:
            return "[ERROR] DNS lookup timed out"
        except Exception as e:
            return f"[ERROR] An unexpected error occurred: {str(e)}"