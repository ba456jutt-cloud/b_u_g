from tools.base import Tool
import subprocess
import json

class WpscanScanTool(Tool):
    name = "wpscan_scan"
    description = "Performs a comprehensive security scan on a WordPress site using WPScan."
    parameters = {
        "url": "Target WordPress URL to scan",
        "options": "Additional WPScan options as a string"
    }

    def execute(self, url: str = None, options: str = "", **kwargs) -> str:
        if not url:
            return "Error: URL parameter is required"

        cmd = ["wpscan", "--url", url]
        if options:
            cmd.extend(options.split())

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                return result.stdout
            else:
                return f"Error: {result.stderr}"
        except subprocess.TimeoutExpired:
            return "Error: WPScan scan timed out"
        except Exception as e:
            return f"Error: {str(e)}"