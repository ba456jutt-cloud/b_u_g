"""
WhatWeb — Web Technology Fingerprinter
Identifies: CMS, frameworks, server software, JS libraries, plugins, versions.
One of the most important recon tools — tells you WHAT is running before you look for CVEs.
"""
import subprocess
from tools.base import Tool

class WhatWebTool(Tool):
    name = "whatweb_fingerprint"
    description = (
        "Fingerprints a website's technology stack: CMS (WordPress, Joomla, Django), "
        "web server (Apache, Nginx, IIS + exact version), programming language, "
        "JS frameworks, jQuery version, cookie flags, email addresses, and more. "
        "Use this FIRST on any web target to know what you're dealing with."
    )
    parameters = {
        "url": "Target URL (e.g. https://example.com)",
        "aggression": "Aggression level 1-4 (1=passive/stealthy, 3=aggressive. Default: 1)"
    }

    def execute(self, url: str = None, target_url: str = None, target: str = None, domain: str = None, aggression: str = "1", **kwargs) -> str:
        url = url or target_url or target or domain or ""
        try:
            if not url.startswith("http"):
                url = "https://" + url
            cmd = ["whatweb", f"--aggression={aggression}", "--no-errors", url]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
            output = result.stdout or result.stderr or "No output"
            return f"=== WhatWeb Fingerprint: {url} ===\n{output}"
        except subprocess.TimeoutExpired:
            return f"WhatWeb timed out for: {url}"
        except FileNotFoundError:
            return "Error: whatweb not installed."
        except Exception as e:
            return f"WhatWeb error: {e}"
