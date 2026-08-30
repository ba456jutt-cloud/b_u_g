import subprocess
from tools.base import Tool

class NucleiTool(Tool):
    name = "nuclei_scan"
    description = "Runs Nuclei vulnerability scanner with community templates against a target URL. Finds common CVEs, misconfigurations, and exposures."
    parameters = {
        "target": "The target URL or IP (e.g. http://example.com)",
        "severity": "Severity level: critical,high,medium,low,info (default: critical,high,medium)"
    }

    def execute(self, target: str, severity: str = "critical,high,medium", **kwargs) -> str:
        try:
            check = subprocess.run(["which", "nuclei"], capture_output=True, text=True)
            if check.returncode != 0:
                return "Nuclei not installed. Run: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

            cmd = [
                "nuclei",
                "-u", target,
                "-severity", severity,
                "-as",                 # automatic scan templates
                "-silent",
                "-no-color",
                "-rate-limit", "10",   # gentle rate limiting
                "-timeout", "5",
                "-c", "5"             # 5 concurrent templates max
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            output = result.stdout or result.stderr
            if not output.strip():
                return f"Nuclei scan completed. No {severity} severity vulnerabilities found for {target}."
            return output
        except subprocess.TimeoutExpired:
            return "Nuclei scan timed out after 3 minutes."
        except Exception as e:
            return f"Nuclei error: {str(e)}"
