from tools.base import Tool
import socket

class DnsPtrTool(Tool):
    name = "dns_ptr"
    description = "Performs a DNS PTR record lookup for a given IP address."
    parameters = {"target": "IP address to lookup"}

    def execute(self, target: str = None, **kwargs) -> str:
        if not target:
            return "Error: No target IP address provided."

        try:
            # Perform the DNS PTR lookup with a timeout of 10 seconds
            domain_name, _, _ = socket.gethostbyaddr(target)
            return f"PTR record for {target}: {domain_name}"
        except socket.herror as e:
            return f"Error: No PTR record found for {target}"
        except socket.gaierror as e:
            return f"Error: Invalid IP address {target}"
        except socket.timeout as e:
            return f"Error: DNS lookup timed out for {target}"
        except Exception as e:
            return f"Error: {str(e)}"