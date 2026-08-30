from tools.base import Tool
import dns.resolver
import dns.exception

class DnsMXTool(Tool):
    name = "dns_mx"
    description = "Queries MX (Mail Exchange) records for a target domain."
    parameters = {"target": "Target domain to query MX records for"}

    def execute(self, target: str = None, **kwargs) -> str:
        if not target:
            return "Error: No target domain provided"

        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '1.1.1.1', '8.8.4.4']
            resolver.timeout = 5
            resolver.lifetime = 5

            answers = resolver.resolve(target, 'MX')
            mx_records = [str(rdata) for rdata in answers]

            return {
                "target": target,
                "mx_records": mx_records
            }
        except dns.exception.Timeout:
            return "Error: DNS query timed out"
        except dns.resolver.NoAnswer:
            return "Error: No MX records found for the target domain"
        except dns.resolver.NXDOMAIN:
            return "Error: The target domain does not exist"
        except dns.resolver.NoNameservers:
            return "Error: No nameservers available to answer the query"
        except Exception as e:
            return f"Error: {str(e)}"