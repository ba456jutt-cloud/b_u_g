import socket
import subprocess
from tools.base import Tool

class WhoisTool(Tool):
    name = "whois_lookup"
    description = "Performs a WHOIS lookup on a domain or IP to gather registration info, owner, nameservers, and contact details."
    parameters = {"target": "Domain name or IP address to look up (e.g. example.com or 192.168.1.1)"}

    def execute(self, target: str = None, domain: str = None, url: str = None, **kwargs) -> str:
        # Accept any common parameter name
        target = target or domain or url or kwargs.get('host', '')
        target = target.replace('https://','').replace('http://','').split('/')[0]
        try:
            # Try using system whois first
            result = subprocess.run(
                ["whois", target],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                # Return first 2000 chars to avoid flooding
                return result.stdout[:2000]

            # Fallback: manual socket connection to whois servers
            whois_server = "whois.iana.org"
            try:
                with socket.create_connection((whois_server, 43), timeout=10) as s:
                    s.sendall(f"{target}\r\n".encode())
                    response = b""
                    while True:
                        data = s.recv(4096)
                        if not data:
                            break
                        response += data
                return response.decode('utf-8', errors='ignore')[:2000]
            except Exception:
                return f"WHOIS lookup failed for {target}. whois tool may not be installed. Run: sudo apt install whois"

        except subprocess.TimeoutExpired:
            return "WHOIS lookup timed out."
        except Exception as e:
            return f"WHOIS error: {str(e)}"
