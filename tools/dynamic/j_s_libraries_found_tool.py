from tools.base import Tool
import requests
import json
import subprocess
import os

class JSLibrariesFoundTool(Tool):
    name = "js_libraries_found"
    description = "Analyzes JavaScript libraries to identify potential security vulnerabilities."
    parameters = {"target": "List of JavaScript library files to analyze"}

    def execute(self, target: list = None, **kwargs) -> str:
        if not target:
            return "Error: No target files provided."

        results = {}

        for js_file in target:
            try:
                # Check if the file exists
                if not os.path.isfile(js_file):
                    results[js_file] = {"error": "File not found"}
                    continue

                # Analyze the JavaScript file for known vulnerabilities
                # Using semgrep for SAST
                cmd = ["semgrep", "--config", "auto", js_file]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                sast_results = result.stdout if result.returncode == 0 else f"Error: {result.stderr}"

                # Fetch the latest CVE data from NVD
                try:
                    resp = requests.get("https://services.nvd.nist.gov/rest/json/cves/1.0", timeout=10)
                    cve_data = resp.json() if resp.status_code == 200 else {}
                except Exception as e:
                    cve_data = {"error": str(e)}

                results[js_file] = {
                    "sast_results": sast_results,
                    "cve_data": cve_data
                }

            except Exception as e:
                results[js_file] = {"error": str(e)}

        return json.dumps(results, indent=2)