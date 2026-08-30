"""
JavaScript Bundle & SPA Route Extractor Tool
=============================================
Parses Single Page Applications (React, Angular, Vue, Next.js) and extracts:
1. Hardcoded REST/GraphQL API Endpoints (/api/v1/..., /rest/...)
2. Client-Side SPA Routes (/#/admin, /#/score-board, /dashboard)
3. Exposed Sensitive Keys & Hidden Parameters inside .js files
"""

import re
import urllib.parse
from typing import List, Dict
from tools.base import StandardSecurityTool

# Regex patterns for SPA routes and API endpoints in JS code
JS_PATTERNS = {
    "api_endpoints": [
        r'["\'](/api/v[0-9]/[a-zA-Z0-9_\-/]+)["\']',
        r'["\'](/rest/[a-zA-Z0-9_\-/]+)["\']',
        r'["\'](/v[0-9]/[a-zA-Z0-9_\-/]+)["\']',
        r'["\'](/graphql[a-zA-Z0-9_\-/]*)["\']',
        r'["\'](/auth/[a-zA-Z0-9_\-/]+)["\']',
    ],
    "spa_routes": [
        r'path:\s*["\']([a-zA-Z0-9_\-/:]+)["\']',
        r'route:\s*["\']([a-zA-Z0-9_\-/:]+)["\']',
        r'["\'](/#/[a-zA-Z0-9_\-/]+)["\']',
        r'["\'](/admin[a-zA-Z0-9_\-/]*)["\']',
        r'["\'](/user[a-zA-Z0-9_\-/]*)["\']',
        r'["\'](/dashboard[a-zA-Z0-9_\-/]*)["\']',
    ],
    "sensitive_keys": [
        r'["\'](api[_-]?key)["\']\s*:\s*["\']([^"\']+)["\']',
        r'["\'](secret[_-]?key)["\']\s*:\s*["\']([^"\']+)["\']',
        r'["\'](token)["\']\s*:\s*["\'](ey[a-zA-Z0-9_\-.]+)["\']',
    ]
}


class JSBundleExtractorTool(StandardSecurityTool):
    name = "js_bundle_extractor"
    description = (
        "Extracts hidden client-side SPA routes (Angular/#/admin, React routes), "
        "REST API endpoints (/rest/user/login, /api/v1/...), and hidden developer keys "
        "from JavaScript bundle files (.js) of modern Single Page Applications (Juice Shop, React/Next.js/Angular)."
    )
    parameters = {
        "url": "Target web application base URL (e.g. http://localhost:3001)"
    }

    def execute(self, url: str, **kwargs) -> str:
        base_url = self.normalize_url(url)
        output_lines = [
            "=== JavaScript Bundle & SPA Endpoint Extractor ===",
            f"Target URL: {base_url}",
            ""
        ]

        # 1. Fetch main page HTML
        resp, err = self.safe_request(base_url, timeout=10)
        if err or not resp:
            return f"Error connecting to target URL: {err}"

        # 2. Extract script src tags
        script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', resp.text, re.IGNORECASE)
        
        # Add common JS bundle names as fallback
        common_bundles = ["main.js", "app.js", "runtime.js", "vendor.js", "polyfills.js", "scripts.js"]
        all_scripts = list(script_srcs)
        for b in common_bundles:
            if b not in all_scripts:
                all_scripts.append(b)

        output_lines.append(f"Discovered Script Bundles ({len(all_scripts)} files):")

        found_apis = set()
        found_routes = set()
        found_secrets = []

        # 3. Download and inspect each JS bundle
        for script in all_scripts[:10]:  # limit to top 10 script files
            script_url = urllib.parse.urljoin(base_url, script)
            js_resp, js_err = self.safe_request(script_url, timeout=8)
            if not js_resp or js_resp.status_code != 200:
                continue

            js_code = js_resp.text
            output_lines.append(f"  - Downloaded: {script} ({len(js_code)} bytes)")

            # Extract API Endpoints
            for pat in JS_PATTERNS["api_endpoints"]:
                matches = re.findall(pat, js_code)
                for m in matches:
                    found_apis.add(m)

            # Extract SPA Routes
            for pat in JS_PATTERNS["spa_routes"]:
                matches = re.findall(pat, js_code)
                for m in matches:
                    if len(m) > 1 and not m.endswith(('.png', '.jpg', '.css', '.svg')):
                        found_routes.add(m)

            # Extract Secrets
            for pat in JS_PATTERNS["sensitive_keys"]:
                matches = re.findall(pat, js_code, re.IGNORECASE)
                for k, v in matches:
                    if len(v) > 4:
                        found_secrets.append(f"{k}: {v[:30]}...")

        # 4. Summarize Discovered SPA Endpoints
        output_lines.append("")
        if found_apis:
            output_lines.append(f"🎯 Discovered Hidden REST API Endpoints ({len(found_apis)} found):")
            for api in sorted(found_apis)[:20]:
                output_lines.append(f"  - {api}")
        else:
            output_lines.append("No explicit REST API endpoints found in JS bundles.")

        output_lines.append("")
        if found_routes:
            output_lines.append(f"🌐 Discovered Client-Side SPA Routes ({len(found_routes)} found):")
            for r in sorted(found_routes)[:20]:
                output_lines.append(f"  - {r}")

        if found_secrets:
            output_lines.append("")
            output_lines.append(f"🔑 Sensitive Developer Keys Discovered ({len(found_secrets)} found):")
            for s in found_secrets[:10]:
                output_lines.append(f"  - {s}")

        return "\n".join(output_lines)
