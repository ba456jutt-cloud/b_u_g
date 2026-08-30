from tools.base import Tool
import requests
import json

class TechStackFetchTool(Tool):
    name = "tech_stack_fetch"
    description = "Analyzes a target website to identify web server, CMS, language, and framework technologies."
    parameters = {"url": "Target URL or hostname"}

    def execute(self, url: str = None, target: str = None, domain: str = None, host: str = None, **kwargs) -> str:
        target_url = url or target or domain or host or ""
        if not target_url:
            return json.dumps({"error": "URL parameter required"})

        if not target_url.startswith("http"):
            target_url = "https://" + target_url

        technologies = []
        try:
            resp = requests.get(target_url, timeout=10, verify=False, allow_redirects=True,
                                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TechAudit/1.0"})
            
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            
            # Header fingerprinting
            if "server" in headers_lower:
                technologies.append(f"Web Server: {headers_lower['server']}")
            if "x-powered-by" in headers_lower:
                technologies.append(f"Backend Language/Framework: {headers_lower['x-powered-by']}")
            if "x-generator" in headers_lower:
                technologies.append(f"CMS/Generator: {headers_lower['x-generator']}")
            if "link" in headers_lower and "wp-json" in headers_lower["link"]:
                technologies.append("CMS: WordPress")
            if "x-litespeed-cache" in headers_lower:
                technologies.append("Cache/Server: LiteSpeed")

            # Content inspection
            body = resp.text.lower()[:5000]
            if "wp-content" in body or "wp-includes" in body:
                if "CMS: WordPress" not in technologies:
                    technologies.append("CMS: WordPress")
            if "elementor" in body:
                technologies.append("Page Builder: Elementor")
            if "woocommerce" in body:
                technologies.append("E-Commerce: WooCommerce")
            if "jquery" in body:
                technologies.append("JS Library: jQuery")

            # Try Wappalyzer if installed
            try:
                from Wappalyzer import Wappalyzer, WebPage
                wappalyzer = Wappalyzer.latest()
                webpage = WebPage.new_from_url(target_url)
                wapp_techs = list(wappalyzer.analyze(webpage))
                if wapp_techs:
                    technologies.extend([f"Wappalyzer: {t}" for t in wapp_techs])
            except Exception:
                pass

            res_data = {
                "url": target_url,
                "status_code": resp.status_code,
                "technologies": list(set(technologies)),
                "headers": dict(resp.headers)
            }
            return json.dumps(res_data, indent=2)

        except Exception as e:
            return json.dumps({"error": f"Tech stack analysis failed: {str(e)}"})