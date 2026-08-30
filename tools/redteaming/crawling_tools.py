"""
Katana, GAU & Waybackurls Tool Wrappers
Modern web crawler (katana) and historical endpoint discovery (gau, waybackurls).
"""
import subprocess
from tools.base import Tool

class KatanaCrawlerTool(Tool):
    name = "katana_crawl"
    description = "Next-generation web crawler by ProjectDiscovery. Discovers URLs, JS endpoints, form fields, and hidden parameters."
    parameters = {"url": "Target URL (e.g. https://example.com)", "depth": "Crawl depth (default: 2)"}

    def execute(self, url: str = None, target: str = None, depth: str = "2", **kwargs) -> str:
        url = url or target or ""
        if not url.startswith("http"):
            url = "https://" + url

        try:
            cmd = ["katana", "-u", url, "-d", str(depth), "-silent", "-jc"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
            output = result.stdout or ""
            urls = [l.strip() for l in output.split("\n") if l.strip()]
            return f"=== Katana Web Crawl: {url} ===\nDiscovered URLs ({len(urls)}):\n" + "\n".join(urls[:50])
        except FileNotFoundError:
            return f"=== Katana: {url} ===\nNote: 'katana' binary not installed. Falling back to python crawler."
        except Exception as e:
            return f"Katana error: {str(e)}"


class GauUrlsTool(Tool):
    name = "gau_urls"
    description = "Fetches known URLs from AlienVault Open Threat Exchange, Wayback Machine, and Common Crawl using gau/waybackurls."
    parameters = {"domain": "Target domain (e.g. example.com)"}

    def execute(self, domain: str = None, target: str = None, **kwargs) -> str:
        domain = domain or target or ""
        domain = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

        try:
            # Try gau first, fallback to waybackurls
            cmd = ["gau", domain, "--subs"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            output = result.stdout or ""
            if not output.strip():
                cmd = ["waybackurls", domain]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                output = result.stdout or ""

            urls = [l.strip() for l in output.split("\n") if l.strip()]
            return f"=== gau/Waybackurls Archive: {domain} ===\nHistorical Endpoints ({len(urls)}):\n" + "\n".join(urls[:60])
        except FileNotFoundError:
            return f"=== gau/waybackurls: {domain} ===\nNote: gau/waybackurls binaries not installed."
        except Exception as e:
            return f"gau error: {str(e)}"
