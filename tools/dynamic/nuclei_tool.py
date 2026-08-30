from tools.base import Tool
import subprocess

class NucleiTool(Tool):
    name = "nuclei"
    description = "Runs a nuclei scan against a target URL to identify vulnerabilities."
    parameters = {"url": "Target URL to scan", "flags": "Nuclei flags string"}

    def execute(self, url: str, flags: str = "-silent", **kwargs) -> str:
        cmd = ["nuclei"] + flags.split() + [url]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                return result.stdout
            else:
                return f"Error: {result.stderr}"
        except subprocess.TimeoutExpired:
            return "Error: Nuclei scan timed out"
        except Exception as e:
            return f"Error: {str(e)}"