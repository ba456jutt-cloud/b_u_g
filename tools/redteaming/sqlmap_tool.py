import subprocess
import re
from tools.base import Tool

class SQLMapTool(Tool):
    name = "sqlmap_scan"
    description = "Tests a URL for SQL injection vulnerabilities using SQLMap. Only for authorized targets."
    parameters = {
        "url": "Target URL with parameter to test (e.g. http://example.com/page?id=1)",
        "target": "Alias for url",
        "data": "POST data string (e.g. 'user=admin&pass=test')",
        "cookie": "Cookie header string",
        "level": "Test level 1-5 (default 3 for CTF speed)",
        "risk": "Risk level 1-3 (default 2 for CTF)"
    }

    def execute(self, url: str = None, target: str = None, data: str = None,
                cookie: str = None, level: int = 3, risk: int = 2, **kwargs) -> str:
        target_url = url or target or kwargs.get("target_url", "")
        if not target_url:
            return "Error: No URL provided. Pass url='http://target.com/page?id=1'"

        try:
            check = subprocess.run(["which", "sqlmap"], capture_output=True, text=True)
            if check.returncode != 0:
                return "SQLMap not installed. Run: sudo apt install sqlmap"

            safe_level = min(max(int(level), 1), 5)
            safe_risk = min(max(int(risk), 1), 3)

            cmd = [
                "sqlmap",
                "-u", target_url,
                "--level", str(safe_level),
                "--risk", str(safe_risk),
                "--batch",
                "--smart",
                "--timeout", "10",
                "--retries", "1",
                "--output-dir", "/tmp/sqlmap_output",
                "--forms",
                "--threads", "3",
            ]

            if data:
                cmd.extend(["--data", str(data)])
            if cookie:
                cmd.extend(["--cookie", str(cookie)])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            output = result.stdout[-4000:] if len(result.stdout) > 4000 else result.stdout

            # Extract key findings
            findings = []
            for line in output.split('\n'):
                if any(kw in line.lower() for kw in ['injectable', 'parameter', 'payload', 'database', 'table', 'column', 'flag']):
                    findings.append(line.strip())

            # Check for flags
            flags = re.findall(r'(flag\{[^}]+\}|CTF\{[^}]+\})', output, re.I)
            if flags:
                findings.append(f"🚩 FLAGS FOUND: {flags}")

            if findings:
                return "=== SQLMap Key Findings ===\n" + "\n".join(findings) + "\n\n=== Full Output ===\n" + output
            return output or result.stderr or "SQLMap completed with no findings."
        except subprocess.TimeoutExpired:
            return "SQLMap timed out after 3 minutes."
        except Exception as e:
            return f"SQLMap error: {str(e)}"

