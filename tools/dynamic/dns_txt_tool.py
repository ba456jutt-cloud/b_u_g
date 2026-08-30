from tools.base import Tool
import dns.resolver

class DnsTxtTool(Tool):
    name = "dns_txt"
    description = "Performs a DNS TXT record lookup for a given target domain."
    parameters = {"target": "Target domain to lookup TXT records for"}

    def execute(self, target: str = None, **kwargs) -> str:
        if not target:
            return "Error: No target domain provided"

        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '1.1.1.1', '8.8.4.4']
            resolver.timeout = 5
            resolver.lifetime = 5
            answers = resolver.resolve(target, 'TXT')
            txt_records = [r.to_text() for r in answers]
            return f"TXT records for {target}: {', '.join(txt_records)}"
        except dns.resolver.NoAnswer:
            return f"No TXT records found for {target}"
        except dns.resolver.NXDOMAIN:
            return f"Domain {target} does not exist"
        except dns.resolver.Timeout:
            return f"Timeout while resolving TXT records for {target}"
        except Exception as e:
            return f"Error: {str(e)}"