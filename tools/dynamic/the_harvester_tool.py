from tools.base import Tool
import subprocess
import json

class TheHarvesterTool(Tool):
    name = "theharvester"
    description = "Performs OSINT gathering using theHarvester to find emails, subdomains, hosts, and other information from public sources."
    parameters = {"target": "Target domain for OSINT gathering"}

    def execute(self, target: str = None, **kwargs) -> str:
        if not target:
            return "Error: Target domain is required"

        try:
            cmd = ["theHarvester", "-d", target, "-b", "all"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                return result.stdout
            else:
                return f"Error: {result.stderr}"
        except subprocess.TimeoutExpired:
            return "Error: The operation timed out"
        except Exception as e:
            return f"Error: {str(e)}"