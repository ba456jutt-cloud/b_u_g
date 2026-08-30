"""
Gitleaks - Secret Scanning for Git Repositories
Requires: gitleaks binary (go install github.com/zricethezav/gitleaks/v8@latest)
"""
import subprocess
from tools.base import Tool

class GitleaksTool(Tool):
    name = "gitleaks_secrets"
    description = "Scans a Git repository for leaked secrets (API keys, passwords, tokens)."
    parameters = {
        "repo": "Local path to repository or remote Git URL",
        "report_format": "Output format: json, csv, sarif (default: json)"
    }

    def execute(self, repo: str = None, target: str = None, report_format: str = "json", **kwargs) -> str:
        repo = repo or target or ""
        if not repo:
            return "Error: Provide a repository path or URL."

        try:
            cmd = ["gitleaks", "detect", "--source", repo, "--report-format", report_format, "--no-banner"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            output = result.stdout or result.stderr
            if result.returncode == 0:
                return f"=== Gitleaks Scan: {repo} ===\nNo leaks found."
            else:
                # Parse findings if json
                if report_format == "json" and output.strip().startswith("["):
                    import json
                    try:
                        findings = json.loads(output)
                        return f"=== Gitleaks: {len(findings)} leaks found ===\n" + "\n".join([f"  - {f.get('RuleID', '')}: {f.get('Description', '')} at {f.get('File', '')}" for f in findings[:20]])
                    except:
                        pass
                return f"=== Gitleaks Scan: {repo} ===\n{output}"
        except FileNotFoundError:
            return "Error: 'gitleaks' not installed. Install with: go install github.com/zricethezav/gitleaks/v8@latest"
        except Exception as e:
            return f"Gitleaks error: {str(e)}"
