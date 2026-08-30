from tools.base import Tool
import dns.resolver
import dns.exception

class DnsCaaTool(Tool):
    name = "dns_caa"
    description = "Queries DNS Certification Authority Authorization (CAA) records for a target domain."
    parameters = {"target": "Domain to query CAA records for"}

    def execute(self, target: str, **kwargs) -> str:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 10
            resolver.lifetime = 10
            answers = resolver.resolve(target, 'CAA')
            caa_records = [str(r) for r in answers]
            return {"status": "success", "records": caa_records}
        except dns.exception.Timeout:
            return {"status": "error", "message": "DNS query timed out"}
        except dns.resolver.NoAnswer:
            return {"status": "error", "message": "No CAA records found"}
        except dns.resolver.NXDOMAIN:
            return {"status": "error", "message": "Domain does not exist"}
        except dns.exception.DNSException as e:
            return {"status": "error", "message": f"DNS error: {str(e)}"}
        except Exception as e:
            return {"status": "error", "message": f"Unexpected error: {str(e)}"}