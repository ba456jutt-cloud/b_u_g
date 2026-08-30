"""
ffuf — Fast Web Fuzzer for Directory/Parameter Discovery
Professional bug bounty tool for:
- Directory and file brute-forcing (find hidden admin panels)
- Virtual host discovery
- Parameter fuzzing
- API endpoint discovery
One of the most used tools in bug bounty programs.
"""
import subprocess
import os
from tools.base import Tool


# Common wordlists — check what's available
WORDLISTS = {
    "common": "/usr/share/wordlists/dirb/common.txt",
    "big": "/usr/share/wordlists/dirb/big.txt",
    "medium": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "api": "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
    "small": "/usr/share/wordlists/dirb/small.txt",
}


class FfufTool(Tool):
    name = "ffuf_fuzz"
    description = (
        "Runs ffuf (Fuzz Faster U Fool) web fuzzer to discover hidden directories, files, "
        "admin panels, API endpoints, and backup files on a target URL. "
        "Replaces FUZZ keyword in the URL — use it as: http://target.com/FUZZ or http://target.com/api/FUZZ. "
        "Filters out common false positives automatically."
    )
    parameters = {
        "url": "Target URL with FUZZ keyword (e.g. https://example.gov.pk/FUZZ or https://example.gov.pk/api/FUZZ)",
        "wordlist": "Wordlist to use: 'common' (fast), 'big' (thorough), 'api' (API endpoints), 'small' (quickest). Default: common",
        "extensions": "File extensions to append (e.g. 'php,asp,aspx,html,txt,bak'. Default: none)"
    }

    def execute(self, url: str, wordlist: str = "common", extensions: str = "", **kwargs) -> str:
        import shutil
        if not shutil.which("ffuf"):
            return "Error: CLI Tool 'ffuf' is not installed on system PATH. Please install via: sudo apt install ffuf or go install github.com/ffuf/ffuf@latest."

        try:
            # Validate FUZZ keyword

            if "FUZZ" not in url:
                url = url.rstrip("/") + "/FUZZ"

            # Select wordlist
            wl_path = WORDLISTS.get(wordlist, WORDLISTS["common"])
            if not os.path.exists(wl_path):
                # Fallback to any available wordlist
                for wl in WORDLISTS.values():
                    if os.path.exists(wl):
                        wl_path = wl
                        break
                else:
                    return "Error: No wordlists found. Install: sudo apt install dirb seclists"

            cmd = [
                "ffuf",
                "-u", url,
                "-w", wl_path,
                "-t", "30",           # 30 threads
                "-rate", "50",        # 50 req/sec — respectful
                "-timeout", "8",
                "-mc", "200,201,204,301,302,307,401,403,405",  # Interesting status codes
                "-fc", "404",         # Filter 404s
                "-fs", "0",           # Filter empty responses
                "-maxtime", "90",     # Max 90 seconds
                "-noninteractive",
                "-v",
            ]

            if extensions:
                cmd.extend(["-e", "." + extensions.replace(",", ",.")])

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120
            )

            output = result.stdout or result.stderr
            if not output.strip():
                return f"ffuf: No interesting paths found on {url}"

            # Parse results
            lines = output.split("\n")
            found = [l for l in lines if "[Status:" in l or "│" in l]
            admin_hits = [l for l in found if any(k in l.lower() for k in ["admin", "login", "dashboard", "backup", "config", "secret"])]

            report = [
                f"=== ffuf Fuzzing Results: {url} ===",
                f"Wordlist: {wl_path}",
                f"Total hits: {len(found)}",
                "",
            ]

            if admin_hits:
                report.append(f"🎯 HIGH-INTEREST FINDINGS ({len(admin_hits)}):")
                report.extend(admin_hits[:15])
                report.append("")

            report.append("--- All Findings ---")
            report.extend(found[:50])

            if len(found) > 50:
                report.append(f"[... {len(found) - 50} more findings truncated ...]")

            return "\n".join(report)

        except subprocess.TimeoutExpired:
            return "ffuf timed out after 120 seconds. Target may be slow or filtering requests."
        except FileNotFoundError:
            return "Error: ffuf not installed. Install: sudo apt install ffuf"
        except Exception as e:
            return f"ffuf error: {type(e).__name__}: {str(e)}"
