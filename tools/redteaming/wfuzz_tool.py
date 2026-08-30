"""
Wfuzz - Web Fuzzer for Parameter, Directory, Subdomain Discovery
Requires: wfuzz (pip install wfuzz)
"""
import subprocess
from tools.base import Tool

class WfuzzTool(Tool):
    name = "wfuzz_fuzz"
    description = "Web fuzzer to discover hidden content, parameters, and subdomains using FUZZ keyword."
    parameters = {
        "url": "Target URL with FUZZ keyword (e.g. http://example.com/FUZZ)",
        "wordlist": "Wordlist path (default: /usr/share/wordlists/wfuzz/general/common.txt)",
        "hc": "Hide response codes (default: 404)"
    }

    def execute(self, url: str = None, target: str = None, wordlist: str = None, hc: str = "404", **kwargs) -> str:
        url = url or target or ""
        if not url:
            return "Error: URL with FUZZ keyword required."

        if "FUZZ" not in url:
            url = url.rstrip("/") + "/FUZZ"

        try:
            if not wordlist:
                wordlist = "/usr/share/wordlists/wfuzz/general/common.txt"
            cmd = ["wfuzz", "-c", "-z", f"file,{wordlist}", "--hc", hc, "-t", "20", url]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            output = result.stdout or result.stderr or ""
            lines = [l for l in output.split("\n") if l.strip() and "Fuzz" not in l]
            return f"=== Wfuzz Results: {url} ===\n" + "\n".join(lines[:50])
        except FileNotFoundError:
            return "Error: 'wfuzz' not installed. Run: pip install wfuzz"
        except subprocess.TimeoutExpired:
            return "Wfuzz timed out."
        except Exception as e:
            return f"Wfuzz error: {str(e)}"
