"""
RustScan - Ultra-Fast Port Scanner (in Rust)
Requires: rustscan binary (docker run rustscan/rustscan or cargo install)
"""
import subprocess
from tools.base import Tool

class RustScanTool(Tool):
    name = "rustscan_portscan"
    description = "Scans all ports ultra-fast using RustScan, then optionally pipes to nmap for service detection."
    parameters = {
        "target": "Target IP or hostname",
        "ports": "Port range (default: 1-65535)",
        "nmap": "Run nmap service detection after (true/false)"
    }

    def execute(self, target: str = None, host: str = None, ports: str = "1-65535", nmap: str = "true", **kwargs) -> str:
        target = target or host or ""
        if not target:
            return "Error: Target IP/host required."

        try:
            cmd = ["rustscan", "-a", target, "-p", ports, "--ulimit", "5000"]
            if nmap.lower() == "true":
                cmd.append("--")
                cmd.extend(["-sV", "-sC", "-oN", "/tmp/rustscan_nmap.txt"])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            output = result.stdout or result.stderr or ""
            # Filter port lines
            ports_found = [l.strip() for l in output.split("\n") if "->" in l or "Port" in l]
            return f"=== RustScan: {target} ===\n" + "\n".join(ports_found[:30])
        except FileNotFoundError:
            return "Error: 'rustscan' not installed. Install via Docker or cargo install rustscan"
        except Exception as e:
            return f"RustScan error: {str(e)}"
