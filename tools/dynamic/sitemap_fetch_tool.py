from tools.base import Tool
import requests
import xml.etree.ElementTree as ET

class SitemapFetchTool(Tool):
    name = "sitemap_fetch"
    description = "Fetches and parses a website's sitemap.xml file to discover hidden or less obvious pages."
    parameters = {"target": "Target URL to inspect", "sitemap_path": "Path to the sitemap file (default: /sitemap.xml)"}

    def execute(self, url: str = None, target: str = None, sitemap_path: str = "/sitemap.xml", **kwargs) -> str:
        target_url = url or target or kwargs.get('domain') or kwargs.get('host') or kwargs.get('target_url') or ""
        if not target_url:
            return "[ERROR] No target URL provided for sitemap fetch."
        if not target_url.startswith("http"):
            target_url = "https://" + target_url
        sitemap_url = f"{target_url.rstrip('/')}{sitemap_path}"
        try:
            resp = requests.get(sitemap_url, timeout=10, verify=False)
            if resp.status_code == 200:
                try:
                    root = ET.fromstring(resp.text)
                    urls = [elem.text for elem in root.iter('{http://www.sitemaps.org/schemas/sitemap/0.9}loc')]
                    return f"Sitemap URLs: {urls}"
                except ET.ParseError as e:
                    return f"[ERROR] Failed to parse sitemap: {str(e)}"
            else:
                return f"[ERROR] Failed to fetch sitemap: HTTP {resp.status_code}"
        except Exception as e:
            return f"[ERROR] Request failed: {str(e)}"