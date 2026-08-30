from tools.base import Tool
import dns.resolver

class DnsNsTool(Tool):
    name = "dns_ns"
    description = "Performs DNS NS record lookup to identify authoritative name servers for a given domain."
    parameters = {"target": "Domain to query for NS records"}

    def execute(self, target: str = None, **kwargs) -> str:
        if not target:
            return "Error: Target domain not specified"

        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 10
            resolver.lifetime = 10
            
            answer = resolver.resolve(target, 'NS')
            
            ns_servers = [str(rr.target) for rr in answer]
            return {"ns_servers": ns_servers}
        except dns.resolver.NoAnswer:
            return "Error: No NS records found for the domain"
        except dns.resolver.NXDOMAIN:
            return "Error: Domain does not exist"
        except dns.resolver.Timeout:
            return "Error: DNS query timed out"
        except dns.resolver.NoNameservers:
            return "Error: No nameservers available"
        except Exception as e:
            return f"Error: {str(e)}"