from tools.base import Tool
import dns.resolver
import dns.exception

class DnsSoaTool(Tool):
    name = "dns_soa"
    description = "Queries DNS SOA (Start of Authority) records for a target domain."
    parameters = {"target": "Target domain to query SOA records for"}

    def execute(self, target: str = None, **kwargs) -> str:
        if not target:
            return "Error: Target domain is required"

        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '1.1.1.1', '8.8.4.4']
            resolver.timeout = 5
            resolver.lifetime = 5

            soa_records = resolver.resolve(target, 'SOA')

            result = {
                "target": target,
                "soa_records": []
            }

            for record in soa_records:
                result["soa_records"].append({
                    "mname": record.mname.to_text(),
                    "rname": record.rname.to_text(),
                    "serial": record.serial,
                    "refresh": record.refresh,
                    "retry": record.retry,
                    "expire": record.expire,
                    "minimum": record.minimum
                })

            return str(result)
        except dns.exception.Timeout:
            return "Error: DNS query timed out"
        except dns.resolver.NoAnswer:
            return "Error: No SOA records found for the target domain"
        except dns.resolver.NXDOMAIN:
            return "Error: The target domain does not exist"
        except dns.resolver.NoNameservers:
            return "Error: No nameservers could be reached"
        except Exception as e:
            return f"Error: {str(e)}"