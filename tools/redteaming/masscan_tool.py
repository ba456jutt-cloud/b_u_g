"""
masscan — Ultra-Fast Port Scanner
Scans the entire internet in 6 minutes. Much faster than nmap for large ranges.
Use for: full port scan (all 65535 ports) where nmap would be too slow.
"""
import subprocess
from tools.base import Tool

class MasscanTool(Tool):
    name = "masscan_portscan"
    description = (
        "Ultra-fast port scanner — much faster than nmap for full port ranges. "
        "Use when you need to scan ALL 65535 ports quickly, or scan large IP ranges. "
        "Pair with nmap afterwards for service/version detection on found ports. "
        "Use rate 1000 for respectful scanning."
    )
    parameters = {
        "target": "Target IP or CIDR range (e.g. 192.168.1.1 or 192.168.1.0/24)",
        "ports": "Port range (e.g. '0-65535' for all, '80,443,8080,8443' for web. Default: 0-65535)",
        "rate": "Scan rate packets/sec (Default: 1000 — be respectful)"
    }

    def execute(self, target: str, ports: str = "0-65535", rate: str = "1000", **kwargs) -> str:
        try:
            cmd = ["masscan", target, "-p", ports, "--rate", rate, "--wait", "2"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            output = result.stdout or result.stderr or "No output"
            return f"=== Masscan: {target} ports={ports} ===\n{output}"
        except subprocess.TimeoutExpired:
            return f"masscan timed out (120s) for: {target}"
        except FileNotFoundError:
            return "Error: masscan not installed."
        except Exception as e:
            return f"masscan error: {e}"
