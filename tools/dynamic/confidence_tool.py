from tools.base import Tool
import subprocess
import socket
import requests
import time

class ConfidenceTool(Tool):
    name = "confidence"
    description = "Performs various security operations on a target system with high confidence."
    parameters = {"target": "IP or hostname", "operation": "Security operation to perform", "flags": "Additional flags for the operation"}

    def execute(self, target: str, operation: str, flags: str = "", **kwargs) -> str:
        try:
            if operation == "nmap_scan":
                cmd = ["nmap"] + flags.split() + [target]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                return result.stdout if result.returncode == 0 else f"Error: {result.stderr}"
            elif operation == "fetch_url":
                target_url = target if target.startswith(('http://', 'https://')) else f"http://{target}"
                resp = requests.get(target_url, timeout=10, verify=False)
                return f"HTTP {resp.status_code}\nHeaders: {dict(resp.headers)}\nBody Snippet: {resp.text[:1000]}"
            elif operation == "port_scan":
                open_ports = []
                common_ports = [21, 22, 80, 443, 3389, 8080]
                for port in common_ports:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        open_ports.append(port)
                    sock.close()
                return f"Open ports: {open_ports}"
            elif operation == "vulnerability_scan":
                cmd = ["nuclei", "-u", target] + flags.split()
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                return result.stdout if result.returncode == 0 else f"Error: {result.stderr}"
            else:
                return f"Unsupported operation: {operation}"
        except subprocess.TimeoutExpired:
            return "Error: Operation timed out"
        except requests.exceptions.RequestException as e:
            return f"Error: Request failed - {str(e)}"
        except socket.error as e:
            return f"Error: Socket operation failed - {str(e)}"
        except Exception as e:
            return f"Error: An unexpected error occurred - {str(e)}"