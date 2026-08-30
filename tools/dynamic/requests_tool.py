from tools.base import Tool
import requests
import json

class RequestsTool(Tool):
    name = "requests"
    description = "A versatile HTTP client for interacting with web applications and APIs."
    parameters = {
        "url": "Target URL to interact with",
        "method": "HTTP method (GET, POST, PUT, DELETE, etc.)",
        "headers": "HTTP headers as a JSON string",
        "data": "Request body data as a JSON string",
        "params": "Query parameters as a JSON string",
        "cookies": "Cookies as a JSON string",
        "timeout": "Request timeout in seconds",
        "proxies": "Proxies as a JSON string",
        "verify": "Verify SSL certificates (True/False)"
    }

    def execute(self, url: str, method: str = "GET", headers: str = None, data: str = None, params: str = None, cookies: str = None, timeout: int = 10, proxies: str = None, verify: bool = True, **kwargs) -> str:
        try:
            headers_dict = json.loads(headers) if headers else None
            data_dict = json.loads(data) if data else None
            params_dict = json.loads(params) if params else None
            cookies_dict = json.loads(cookies) if cookies else None
            proxies_dict = json.loads(proxies) if proxies else None

            response = requests.request(
                method=method.upper(),
                url=url,
                headers=headers_dict,
                data=data_dict,
                params=params_dict,
                cookies=cookies_dict,
                timeout=timeout,
                proxies=proxies_dict,
                verify=verify
            )

            return json.dumps({
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "text": response.text,
                "cookies": dict(response.cookies),
                "url": response.url,
                "history": [{
                    "status_code": r.status_code,
                    "url": r.url
                } for r in response.history]
            })
        except requests.exceptions.RequestException as e:
            return json.dumps({"error": f"Request failed: {str(e)}"})
        except json.JSONDecodeError as e:
            return json.dumps({"error": f"Invalid JSON input: {str(e)}"})
        except Exception as e:
            return json.dumps({"error": f"An unexpected error occurred: {str(e)}"})