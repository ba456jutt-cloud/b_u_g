from tools.base import Tool
import whois
import socket

class WhoisTool(Tool):
    name = "whois_lookup"
    description = "Performs a WHOIS lookup on a target domain or IP address."
    parameters = {"target": "Domain or IP address to query"}

    def execute(self, target: str = None, **kwargs) -> str:
        if not target:
            return "Error: No target specified"

        try:
            # Set a timeout for the WHOIS query
            socket.setdefaulttimeout(10)
            
            # Perform the WHOIS lookup
            domain_info = whois.whois(target)

            # Format the result
            result = {
                "domain": target,
                "registrar": domain_info.registrar,
                "creation_date": domain_info.creation_date,
                "expiration_date": domain_info.expiration_date,
                "name_servers": domain_info.name_servers,
                "status": domain_info.status,
                "emails": domain_info.emails,
                "dnssec": domain_info.dnssec,
                "name": domain_info.name,
                "org": domain_info.org,
                "address": domain_info.address,
                "city": domain_info.city,
                "state": domain_info.state,
                "zipcode": domain_info.zipcode,
                "country": domain_info.country
            }

            return str(result)
        except Exception as e:
            return f"Error: {str(e)}"