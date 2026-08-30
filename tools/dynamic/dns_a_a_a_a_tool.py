from tools.base import Tool
import socket

class DnsAAAATool(Tool):
    name = "dns_aaaa"
    description = "Performs a DNS AAAA record lookup to identify IPv6 addresses associated with a target domain."
    parameters = {"target": "Domain name to query"}

    def execute(self, target: str = None, **kwargs) -> str:
        if not target:
            return "Error: Target domain not specified"

        try:
            # Perform DNS AAAA record lookup
            addresses = socket.getaddrinfo(target, None, socket.AF_INET6)
            ipv6_addresses = [addr[4][0] for addr in addresses]
            return f"IPv6 addresses found for {target}: {', '.join(ipv6_addresses)}"
        except socket.gaierror as e:
            return f"Error: DNS lookup failed - {str(e)}"
        except Exception as e:
            return f"Error: An unexpected error occurred - {str(e)}"