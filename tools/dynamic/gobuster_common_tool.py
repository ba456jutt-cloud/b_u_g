from tools.base import Tool
import subprocess
import os

class GobusterCommonTool(Tool):
    name = "gobuster_common"
    description = "Performs a directory brute-force scan using gobuster with wildcard handling."
    parameters = {"url": "Target URL to scan", "wordlist_type": "Type of wordlist to use (common, directories, files)"}

    def execute(self, url: str = None, target: str = None, wordlist_type: str = "common", **kwargs) -> str:
        url = url or target or ""
        if not url:
            return "Error: Target URL parameter is required"

        if not url.startswith("http"):
            url = "https://" + url

        # Find wordlist
        wl_path = "/usr/share/wordlists/dirb/common.txt"
        if not os.path.exists(wl_path):
            wl_path = "/usr/share/dirb/wordlists/common.txt"
        if not os.path.exists(wl_path):
            wl_path = "/usr/share/wordlists/dirb/small.txt"

        cmd = [
            "gobuster", "dir",
            "-u", url,
            "-w", wl_path,
            "-t", "20",
            "--timeout", "8s",
            "--wildcard",
            "-b", "403,404,500",
            "--exclude-length", "787,795,0",
            "-q",
            "--no-error",
            "--no-tls-validation"
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            output = result.stdout or result.stderr or "No paths found."
            return f"=== Gobuster Common Results for {url} ===\n{output}"
        except subprocess.TimeoutExpired:
            return "Error: Gobuster scan timed out after 120 seconds."
        except Exception as e:
            return f"Error executing Gobuster: {str(e)}"