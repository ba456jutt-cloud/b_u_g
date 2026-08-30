from tools.base import Tool
import subprocess

class SubfinderTool(Tool):
    name = "subfinder_discovery"
    description = "Discovers subdomains for a given target using the subfinder tool."
    parameters = {"target": "Target domain to discover subdomains for", "flags": "Additional subfinder flags"}

    def execute(self, target: str = None, flags: str = "", **kwargs) -> str:
        if not target:
            return "Error: Target domain is required"
        
        cmd = ["subfinder", "-d", target] + flags.split()
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return result.stdout if result.returncode == 0 else f"Error: {result.stderr}"
        except subprocess.TimeoutExpired:
            return "Error: Subfinder command timed out"
        except Exception as e:
            return f"Error: {str(e)}"