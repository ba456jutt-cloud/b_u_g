from tools.base import Tool
import requests
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CurlFetchTool(Tool):
    name = "curl_fetch"
    description = "Fetches web page content and headers over HTTP/HTTPS."
    parameters = {"url": "Target URL to fetch"}

    def execute(self, url: str = None, target: str = None, method: str = "GET", headers: dict = None, **kwargs) -> str:
        raw_url = url or target or kwargs.get("domain") or ""
        raw_url = str(raw_url).strip()
        if not raw_url:
            return "[ERROR] URL parameter required"

        if not raw_url.startswith("http"):
            raw_url = "https://" + raw_url

        try:
            req_headers = headers if isinstance(headers, dict) else {}
            if "User-Agent" not in req_headers:
                req_headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CurlFetch/1.0"

            response = requests.request(
                method.upper(),
                raw_url,
                headers=req_headers,
                timeout=12,
                verify=False,
                allow_redirects=True
            )

            headers_str = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
            return f"HTTP {response.status_code}\nURL: {response.url}\nHEADERS:\n{headers_str}\n\nBODY SNIPPET:\n{response.text[:1500]}"
        except requests.exceptions.SSLError:
            try:
                response = requests.get(raw_url, timeout=12, verify=False)
                return f"HTTP {response.status_code} (SSL Warning)\n{response.text[:1000]}"
            except Exception as e:
                return f"[ERROR] SSL request failed: {e}"
        except Exception as e:
            return f"[ERROR] Request failed: {str(e)}"