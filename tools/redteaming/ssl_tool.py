import ssl
import socket
from datetime import datetime
from tools.base import Tool

class SSLCheckerTool(Tool):
    name = "ssl_check"
    description = "Checks SSL/TLS certificate of a domain: expiry date, issuer, subject, protocol version, and weak cipher detection."
    parameters = {"host": "Hostname to check (e.g. example.com)", "port": "Port number (default: 443)"}

    def execute(self, host: str = None, target: str = None, domain: str = None, url: str = None, port: int = 443, **kwargs) -> str:
        # Accept any common parameter name
        host = host or target or domain or url or ''
        try:
            # Strip http/https prefix if present
            host = host.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

            context = ssl.create_default_context()
            results = []

            with socket.create_connection((host, int(port)), timeout=30) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
                    cipher = ssock.cipher()

                    # Parse expiry
                    expiry_str = cert.get('notAfter', 'Unknown')
                    try:
                        expiry_dt = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                        days_left = (expiry_dt - datetime.utcnow()).days
                        expiry_info = f"{expiry_str} ({days_left} days remaining)"
                        if days_left < 30:
                            expiry_info += " ⚠️ EXPIRING SOON!"
                        if days_left < 0:
                            expiry_info += " 🚨 EXPIRED!"
                    except Exception:
                        expiry_info = expiry_str

                    # Subject / Issuer
                    subject = dict(x[0] for x in cert.get('subject', []))
                    issuer = dict(x[0] for x in cert.get('issuer', []))

                    results.append(f"=== SSL/TLS Report for {host}:{port} ===")
                    results.append(f"Common Name:    {subject.get('commonName', 'N/A')}")
                    results.append(f"Issuer:         {issuer.get('organizationName', 'N/A')}")
                    results.append(f"Valid Until:    {expiry_info}")
                    results.append(f"Protocol:       {protocol}")
                    results.append(f"Cipher:         {cipher[0] if cipher else 'Unknown'}")
                    results.append(f"Cipher Bits:    {cipher[2] if cipher else 'Unknown'}")

                    # Check for weak protocols
                    weak_protocols = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
                    if protocol in weak_protocols:
                        results.append(f"⚠️  VULNERABILITY: Weak protocol {protocol} in use!")

                    # Check for weak cipher
                    if cipher and cipher[2] and int(cipher[2]) < 128:
                        results.append(f"⚠️  VULNERABILITY: Weak cipher strength ({cipher[2]} bits)")

                    # SANs
                    san = cert.get('subjectAltName', [])
                    if san:
                        san_list = [s[1] for s in san]
                        results.append(f"SANs:           {', '.join(san_list[:10])}")

            return "\n".join(results)

        except ssl.SSLCertVerificationError as e:
            return f"SSL Certificate Verification FAILED: {e}\n⚠️ This may indicate an invalid or self-signed certificate!"
        except ssl.SSLError as e:
            return f"SSL Error: {e}"
        except ConnectionRefusedError:
            return f"Connection refused to {host}:{port}"
        except Exception as e:
            return f"SSL Check error: {str(e)}"
