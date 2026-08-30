from tools.base import Tool
import subprocess
import json

class WpscanFindingsTool(Tool):
    name = "wpscan_findings"
    description = "Uses WPScan to enumerate WordPress site components and configurations."
    parameters = {"url": "Target WordPress URL", "enumerate": "Comma-separated list of enumeration types (ap, at, tt, cb, dbe)"}

    def execute(self, url: str, enumerate: str = "ap,at,tt,cb,dbe", **kwargs) -> str:
        try:
            cmd = ["wpscan", "--url", url, "--enumerate", enumerate]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                findings = {
                    "url": url,
                    "findings": result.stdout
                }
                return json.dumps(findings, indent=2)
            else:
                return json.dumps({"error": f"WPScan failed: {result.stderr}"})
        except subprocess.TimeoutExpired:
            return json.dumps({"error": "WPScan timed out after 300 seconds"})
        except Exception as e:
            return json.dumps({"error": f"An unexpected error occurred: {str(e)}"})