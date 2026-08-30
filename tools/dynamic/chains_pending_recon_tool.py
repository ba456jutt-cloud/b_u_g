from tools.base import Tool
import requests
import subprocess
import json

class ChainsPendingReconTool(Tool):
    name = "chains_pending_recon"
    description = "Identifies pending or incomplete security chains on a target system."
    parameters = {"target": "IP or hostname"}

    def execute(self, target: str, **kwargs) -> str:
        try:
            # Perform an initial HTTP request to the target
            resp = requests.get(f"http://{target}", timeout=10, verify=False)
            
            # Check for common security headers
            security_headers = {
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "default-src 'self'"
            }
            
            missing_headers = [header for header, value in security_headers.items() if header not in resp.headers or resp.headers[header] != value]
            
            # Run an Nmap scan to identify open ports and services
            nmap_cmd = ["nmap", "-sV", "-T4", target]
            nmap_result = subprocess.run(nmap_cmd, capture_output=True, text=True, timeout=300)
            
            # Run a Nikto scan to identify potential vulnerabilities
            nikto_cmd = ["nikto", "-h", target]
            nikto_result = subprocess.run(nikto_cmd, capture_output=True, text=True, timeout=300)
            
            # Compile the results
            results = {
                "security_headers": {
                    "missing": missing_headers,
                    "present": [header for header in security_headers if header in resp.headers]
                },
                "nmap_scan": nmap_result.stdout if nmap_result.returncode == 0 else f"Error: {nmap_result.stderr}",
                "nikto_scan": nikto_result.stdout if nikto_result.returncode == 0 else f"Error: {nikto_result.stderr}"
            }
            
            return json.dumps(results)
        except requests.exceptions.RequestException as e:
            return f"[ERROR] Request failed: {str(e)}"
        except subprocess.TimeoutExpired:
            return "[ERROR] Subprocess timed out"
        except Exception as e:
            return f"[ERROR] An unexpected error occurred: {str(e)}"