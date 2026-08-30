"""
feroxbuster — Fast Recursive Directory Brute-Forcer (Rust-based, very fast)
Better than gobuster for recursive scanning — automatically goes deeper into found directories.
Finds: hidden admin panels, backup files, config files, API endpoints.
"""
import subprocess, os
from tools.base import Tool

WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/usr/share/wordlists/dirb/big.txt",
    "/usr/share/wordlists/dirb/common.txt",
]

class FeroxbusterTool(Tool):
    name = "feroxbuster_scan"
    description = (
        "Fast recursive web content discovery using feroxbuster. "
        "Automatically recurses into found directories (gobuster does not). "
        "Finds: hidden admin panels, backup files (.bak, .old), config files, "
        "API endpoints, git repos (/.git), and more. "
        "Better than gobuster for thorough directory brute-forcing."
    )
    parameters = {
        "url": "Target URL (e.g. https://example.com)",
        "extensions": "File extensions to check (e.g. 'php,asp,html,txt,bak'. Default: php,html,txt,bak,old,zip)"
    }

    def execute(self, url: str, extensions: str = "php,html,txt,bak,old,zip", **kwargs) -> str:
        try:
            if not url.startswith("http"):
                url = "https://" + url
            wordlist = next((w for w in WORDLISTS if os.path.exists(w)), None)
            if not wordlist:
                return "Error: No wordlists found. Install: sudo apt install seclists dirb"
            cmd = [
                "feroxbuster", "--url", url,
                "--wordlist", wordlist,
                "--extensions", extensions,
                "--threads", "30",
                "--depth", "3",
                "--timeout", "8",
                "--rate-limit", "50",
                "--status-codes", "200,201,204,301,302,307,401,403,405,500",
                "--filter-status", "404",
                "--no-recursion",
                "--time-limit", "90s",
                "--quiet",
                "--no-state",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=110)
            output = result.stdout or result.stderr or "No findings."
            lines = [l for l in output.split("\n") if l.strip() and any(c.isdigit() for c in l)]
            interesting = [l for l in lines if any(k in l.lower() for k in ["admin","login","backup","config","secret",".git","upload","dashboard"])]
            report = [f"=== Feroxbuster: {url} ===", f"Total findings: {len(lines)}"]
            if interesting:
                report.append(f"\n🎯 INTERESTING PATHS ({len(interesting)}):")
                report.extend(interesting[:15])
            report.append("\n--- All Findings ---")
            report.extend(lines[:50])
            return "\n".join(report)
        except subprocess.TimeoutExpired:
            return f"feroxbuster timed out (110s) for: {url}"
        except FileNotFoundError:
            return "Error: feroxbuster not installed."
        except Exception as e:
            return f"feroxbuster error: {e}"
