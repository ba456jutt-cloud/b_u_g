from tools.base import Tool
import requests
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SensitiveFilesTool(Tool):
    name = "sensitive_files"
    description = "Scans a target system for sensitive files and directories (.git, .env, wp-config, etc.)."
    parameters = {"target": "IP or hostname"}

    def execute(self, target: str = None, url: str = None, host: str = None, **kwargs) -> str:
        raw = target or url or host or ""
        raw = str(raw).strip()
        if not raw:
            return json.dumps({"error": "Target parameter is required"})

        # Clean scheme and domain to avoid http://https:// URL corruption
        if not raw.startswith("http"):
            base_url = f"https://{raw}"
        else:
            base_url = raw
        
        # Remove trailing slash
        base_url = base_url.rstrip("/")

        sensitive_files = [
            "/.git/HEAD",
            "/.env",
            "/.htaccess",
            "/.htpasswd",
            "/config.php",
            "/wp-config.php",
            "/database.sql",
            "/backup.zip",
            "/phpinfo.php",
            "/robots.txt",
            "/sitemap.xml",
            "/.well-known/security.txt"
        ]

        found_files = []

        for file_path in sensitive_files:
            clean_path = file_path if file_path.startswith("/") else "/" + file_path
            target_file_url = f"{base_url}{clean_path}"
            try:
                response = requests.get(target_file_url, timeout=5, verify=False, allow_redirects=False,
                                        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecCheck/1.0"})
                if response.status_code == 200:
                    found_files.append({"path": file_path, "status": "Found (200 OK)", "url": target_file_url})
                elif response.status_code in (301, 302, 403):
                    found_files.append({"path": file_path, "status": f"Protected/Redirect ({response.status_code})", "url": target_file_url})
            except Exception:
                pass

        res = {
            "target": base_url,
            "scanned_paths": len(sensitive_files),
            "findings": found_files if found_files else "No publicly accessible sensitive files found."
        }
        return json.dumps(res, indent=2)