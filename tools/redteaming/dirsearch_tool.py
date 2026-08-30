"""
dirsearch - Advanced Directory Brute-Forcer
Requires: dirsearch (pip install dirsearch or git clone)
"""
import subprocess
from tools.base import Tool

class DirsearchTool(Tool):
    name = "dirsearch_scan"
    description = "Advanced web directory bruteforcer with recursive scanning, extension fuzzing, and report generation."
    parameters = {
        "url": "Target URL (e.g. https://example.com)",
        "extensions": "File extensions (e.g. php,html,txt)",
        "wordlist": "Path to custom wordlist (optional)"
    }

    def execute(self, url: str = None, target: str = None, extensions: str = "", wordlist: str = None, **kwargs) -> str:
        url = url or target or ""
        if not url:
            return "Error: URL required."

        try:
            cmd = ["dirsearch", "-u", url, "--threads=20", "--timeout=5", "--random-agent", "--exclude-status=404"]
            if extensions:
                cmd.extend(["-e", extensions])
            if wordlist:
                cmd.extend(["-w", wordlist])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            output = result.stdout or result.stderr or ""
            # Extract findings
            lines = output.split("\n")
            findings = [l for l in lines if "[" in l and ("200" in l or "301" in l or "403" in l or "500" in l)]
            return f"=== Dirsearch: {url} ===\nFound {len(findings)} paths:\n" + "\n".join(findings[:60])
        except FileNotFoundError:
            return "Error: 'dirsearch' not installed. Install: pip install dirsearch"
        except subprocess.TimeoutExpired:
            return f"Dirsearch timed out for {url}"
        except Exception as e:
            return f"Dirsearch error: {str(e)}"
