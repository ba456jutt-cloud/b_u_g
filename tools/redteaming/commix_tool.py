"""
Commix - Command Injection Exploitation Tool
Requires: commix (apt install commix or git clone)
"""
import subprocess
from tools.base import Tool

class CommixTool(Tool):
    name = "commix_injection"
    description = "Detects and exploits command injection vulnerabilities using Commix (safe mode)."
    parameters = {
        "url": "Target URL (e.g. http://example.com/page?ip=127.0.0.1)",
        "data": "POST data string (optional)",
        "level": "Test level 1-3 (default: 2)"
    }

    def execute(self, url: str = None, target: str = None, data: str = None, level: int = 2, **kwargs) -> str:
        url = url or target or ""
        if not url:
            return "Error: URL required."

        try:
            cmd = ["commix", "--url", url, "--level", str(level), "--batch", "--timeout=5"]
            if data:
                cmd.extend(["--data", data])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            output = result.stdout or result.stderr or ""
            # Extract key lines
            lines = [l for l in output.split("\n") if any(k in l.lower() for k in ["injectable", "vulnerable", "command", "payload", "success"])]
            return f"=== Commix Scan: {url} ===\n" + "\n".join(lines[:40])
        except FileNotFoundError:
            return "Error: 'commix' not installed. Run: apt install commix"
        except subprocess.TimeoutExpired:
            return "Commix timed out."
        except Exception as e:
            return f"Commix error: {str(e)}"
