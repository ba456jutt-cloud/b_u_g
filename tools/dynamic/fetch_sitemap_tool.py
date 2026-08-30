from tools.base import Tool
import requests
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

class FetchSitemapTool(Tool):
    name = "fetch_sitemap"
    description = "Fetches and parses a sitemap.xml file from a target URL."
    parameters = {"url": "URL of the sitemap.xml file to fetch"}

    def execute(self, url: str = None, target: str = None, **kwargs) -> str:
        target_url = url or target or kwargs.get('url') or "https://scholarhub.online/sitemap.xml"
        
        # Validate the URL
        parsed_url = urlparse(target_url)
        if not all([parsed_url.scheme, parsed_url.netloc]) or not target_url.endswith("sitemap.xml"):
            return "[ERROR] Invalid URL. Please provide a valid URL ending with 'sitemap.xml'."
        
        try:
            # Fetch the sitemap content
            response = requests.get(target_url, timeout=10, verify=False)
            response.raise_for_status()
            
            # Parse the XML content
            root = ET.fromstring(response.content)
            urls = [elem.text for elem in root.iter('{http://www.sitemaps.org/schemas/sitemap/0.9}loc')]
            
            return {"urls": urls}
        except requests.exceptions.RequestException as e:
            return f"[ERROR] Request failed: {str(e)}"
        except ET.ParseError as e:
            return f"[ERROR] Failed to parse XML: {str(e)}"
        except Exception as e:
            return f"[ERROR] An unexpected error occurred: {str(e)}"