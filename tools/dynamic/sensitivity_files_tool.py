from tools.base import Tool
import requests
from typing import List, Dict

class SensitivityFilesTool(Tool):
    name = "sensitivity_files"
    description = "Identifies and analyzes sensitive files on a target web server."
    parameters = {"target": "Target URL to scan for sensitive files"}

    def execute(self, target: str = None, **kwargs) -> str:
        target_url = target or kwargs.get('url') or kwargs.get('domain') or kwargs.get('host') or "https://scholarhub.online"
        
        if not target_url.startswith(('http://', 'https://')):
            target_url = f"https://{target_url}"

        sensitive_files = [
            "/.git/",
            "/.env",
            "/.gitignore",
            "/.htaccess",
            "/.htpasswd",
            "/config.php",
            "/wp-config.php",
            "/database.sql",
            "/backup.zip",
            "/robots.txt",
            "/sitemap.xml",
            "/admin",
            "/login",
            "/wp-admin",
            "/phpinfo.php",
            "/server-status",
            "/phpmyadmin",
            "/test.php",
            "/LICENSE",
            "/README.md",
            "/CHANGELOG.md",
            "/composer.json",
            "/package.json",
            "/yarn.lock",
            "/package-lock.json"
        ]

        found_files: List[Dict[str, str]] = []

        try:
            for file_path in sensitive_files:
                url = f"{target_url.rstrip('/')}{file_path}"
                try:
                    resp = requests.get(url, timeout=10, verify=False)
                    if resp.status_code != 404:
                        found_files.append({
                            "path": file_path,
                            "status_code": resp.status_code,
                            "size": len(resp.content)
                        })
                except requests.exceptions.RequestException as e:
                    continue

            if found_files:
                return f"Found sensitive files: {found_files}"
            else:
                return "No sensitive files found."
        except Exception as e:
            return f"[ERROR] Scan failed: {str(e)}"