import requests
from bs4 import BeautifulSoup
from tools.base import Tool

class FetchURLTool(Tool):
    name = "fetch_url"
    description = "Fetches the HTML content and headers from a provided URL. Use this to analyze websites."

    def execute(self, url: str, **kwargs) -> str:
        try:
            # Ensure URL has scheme
            if not url.startswith("http://") and not url.startswith("https://"):
                url = "http://" + url

            headers = {
                'User-Agent': 'BugBountyCopilot/1.0 (Defensive Research Assistant)'
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            
            # Extract basic info
            status_code = response.status_code
            server_header = response.headers.get('Server', 'Unknown')
            powered_by = response.headers.get('X-Powered-By', 'Unknown')
            
            # Extract plain text from HTML for token efficiency
            soup = BeautifulSoup(response.text, 'html.parser')
            text_content = soup.get_text(separator=' ', strip=True)
            
            # Truncate content to avoid overwhelming the LLM prompt context
            if len(text_content) > 3000:
                text_content = text_content[:3000] + "\n...[TRUNCATED]..."

            output = f"Status Code: {status_code}\n"
            output += f"Server: {server_header}\n"
            output += f"X-Powered-By: {powered_by}\n"
            output += f"\n--- Page Content Summary ---\n{text_content}\n"
            
            return output
        except requests.exceptions.Timeout:
            return f"Error: Request to {url} timed out."
        except Exception as e:
            return f"Error fetching URL {url}: {str(e)}"
