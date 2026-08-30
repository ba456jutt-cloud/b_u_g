"""
Shodan - Internet Connected Device Search Engine
Requires: shodan CLI (pip install shodan) and SHODAN_API_KEY environment variable
"""
import subprocess
import os
from tools.base import Tool

class ShodanTool(Tool):
    name = "shodan_search"
    description = "Searches Shodan for internet-facing assets (IPs, services, vulnerabilities). Requires SHODAN_API_KEY."
    parameters = {
        "query": "Shodan search query (e.g. 'product:Apache country:PK')",
        "limit": "Number of results to display (default: 10)"
    }

    def execute(self, query: str = None, target: str = None, limit: int = 10, **kwargs) -> str:
        query = query or target or ""
        if not query:
            return "Error: Provide a Shodan search query."

        try:
            api_key = os.environ.get("SHODAN_API_KEY")
            if not api_key:
                return "Error: SHODAN_API_KEY environment variable not set."

            cmd = ["shodan", "search", "--limit", str(limit), query]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return f"=== Shodan Results for '{query}' ===\n{result.stdout or result.stderr}"
        except FileNotFoundError:
            return "Error: 'shodan' CLI not installed. Run: pip install shodan"
        except Exception as e:
            return f"Shodan error: {str(e)}"
