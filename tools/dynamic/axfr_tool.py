from tools.base import Tool
import subprocess

class AxfrTool(Tool):
    name = "axfr"
    description = "Performs a DNS zone transfer (AXFR) against a target domain."
    parameters = {"target": "Target domain to perform AXFR on"}

    def execute(self, target: str = None, **kwargs) -> str:
        if not target:
            return "Error: Target domain not specified"

        try:
            cmd = ["dig", "axfr", target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.stdout if result.returncode == 0 else f"Error: {result.stderr}"
        except subprocess.TimeoutExpired:
            return "Error: DNS zone transfer timed out"
        except Exception as e:
            return f"Error: {str(e)}"