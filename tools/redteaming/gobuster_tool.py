import subprocess
import os
from tools.base import Tool

# Wordlist priority order — smallest/fastest first for agents
WORDLISTS = {
    "small":  [
        "/usr/share/wordlists/dirb/small.txt",
        "/usr/share/dirb/wordlists/small.txt",
    ],
    "common": [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/dirb/wordlists/common.txt",
    ],
    "big": [
        "/usr/share/wordlists/dirb/big.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    ],
    "api": [
        "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
        "/usr/share/wordlists/dirb/common.txt",
    ],
}

def find_wordlist(wl_type: str) -> str | None:
    paths = WORDLISTS.get(wl_type, WORDLISTS["small"])
    return next((p for p in paths if os.path.exists(p)), None)


class GobusterTool(Tool):
    name = "gobuster_scan"
    description = (
        "Brute-forces hidden directories and files on a web server. "
        "Finds: admin panels, backup files, config files, API endpoints, hidden paths. "
        "Use wordlist_type='small' for quick scan (500 words, ~30s), "
        "'common' for standard (4000 words, ~2min), 'big' for thorough. "
        "Default: 'small' — agents should start small then go bigger if needed."
    )
    parameters = {
        "url": "Target URL (e.g. https://example.com)",
        "wordlist_type": "Wordlist size: 'small' (fast/default), 'common', 'big', 'api'",
        "wordlist": "Direct path to wordlist file (overrides wordlist_type)",
        "extensions": "File extensions to try (e.g. 'php,html,txt,bak')",
    }

    def execute(self, url: str = None, target: str = None,
                wordlist_type: str = "small", wordlist: str = None,
                extensions: str = "", **kwargs) -> str:
        # Accept 'target' or 'url'
        url = url or target or ""
        if not url:
            return "Error: provide 'url' parameter"

        try:
            if not url.startswith("http"):
                # Use http:// for bare IPs, https:// for domains
                import re as _re
                if _re.match(r'^\d{1,3}(\.\d{1,3}){3}', url):
                    url = "http://" + url
                else:
                    url = "https://" + url

            # Select wordlist
            if wordlist and os.path.exists(wordlist):
                wl_path = wordlist
            else:
                wl_path = find_wordlist(wordlist_type) or find_wordlist("small") or find_wordlist("common")

                if not wl_path:
                    # Last resort fallback
                    for wt in ["small", "common", "big"]:
                        wl_path = find_wordlist(wt)
                        if wl_path:
                            break
                if not wl_path:
                    return "Error: No wordlists found. Install: sudo apt install dirb seclists"

            # Timeout: small=120s, common=180s, big=240s
            timeouts = {"small": 120, "common": 180, "big": 240, "api": 150}
            timeout_sec = timeouts.get(wordlist_type, 120)

            cmd = [
                "gobuster", "dir",
                "-u", url,
                "-w", wl_path,
                "-t", "20",
                "--timeout", "8s",
                "-b", "403,404",
                "--exclude-length", "787,0",
                "-q",
                "--no-error",
                "--no-tls-validation",
            ]

            if extensions:
                cmd.extend(["-x", extensions])

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout_sec
            )

            output = result.stdout or result.stderr or ""
            lines = [l.strip() for l in output.strip().split("\n") if l.strip()]

            if not lines:
                return (
                    f"=== Gobuster: {url} ===\n"
                    f"Wordlist: {wl_path}\n"
                    f"No directories found. Target may have custom 404 pages or WAF.\n"
                    f"Try: wordlist_type='common' or add extensions='php,html'"
                )

            interesting = [l for l in lines if any(
                k in l.lower() for k in ["admin","login","dashboard","backup","config",
                                          "secret","upload","manager","phpmyadmin"]
            )]

            report = [
                f"=== Gobuster: {url} ===",
                f"Wordlist: {os.path.basename(wl_path)} | Found: {len(lines)} paths",
                "",
            ]
            if interesting:
                report.append(f"🎯 INTERESTING PATHS ({len(interesting)}):")
                report.extend(interesting[:20])
                report.append("")

            report.append("--- All Found Paths ---")
            report.extend(lines[:60])
            if len(lines) > 60:
                report.append(f"[... {len(lines)-60} more paths not shown ...]")

            return "\n".join(report)

        except subprocess.TimeoutExpired:
            return (
                f"Gobuster timed out ({timeout_sec}s) for: {url}\n"
                f"Target is slow or wordlist too large.\n"
                f"Try: wordlist_type='small' or reduce extensions."
            )
        except Exception as e:
            return f"Gobuster error: {type(e).__name__}: {str(e)}"
