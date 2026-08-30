from tools.base import Tool
import requests
import subprocess
import json

class ToolCalls(Tool):
    name = "tool_calls"
    description = "Orchestrates multiple security operations including fetching URLs and performing a nuclei scan."
    parameters = {
        "target": "List of operations to perform"
    }

    def execute(self, target: list = None, **kwargs) -> str:
        results = {}
        
        if not target:
            return json.dumps({"error": "No target operations provided"})
        
        for operation in target:
            try:
                if operation['name'] == 'fetch_url':
                    url = operation['arguments']['url']
                    results[url] = self.fetch_url(url)
                elif operation['name'] == 'nuclei_scan':
                    target_url = operation['arguments']['target']
                    severity = operation['arguments']['severity']
                    results['nuclei_scan'] = self.nuclei_scan(target_url, severity)
            except Exception as e:
                results[operation['name']] = f"Error executing {operation['name']}: {str(e)}"
        
        return json.dumps(results)

    def fetch_url(self, url: str) -> str:
        try:
            resp = requests.get(url, timeout=10, verify=False)
            return {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body_snippet": resp.text[:1000]
            }
        except Exception as e:
            return {"error": f"Request failed: {str(e)}"}

    def nuclei_scan(self, target: str, severity: list) -> str:
        cmd = ["nuclei", "-u", target, "-severity", ",".join(severity)]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                return {
                    "output": result.stdout
                }
            else:
                return {
                    "error": result.stderr
                }
        except Exception as e:
            return {"error": f"Nuclei scan failed: {str(e)}"}