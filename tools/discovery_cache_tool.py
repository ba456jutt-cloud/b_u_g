"""
DiscoveryCacheTool - Stores and retrieves basic recon findings
Prevents repetitive calls to dns_lookup, whois, ssl_check, etc.
"""
import os
import json
from tools.base import Tool

class DiscoveryCacheTool(Tool):
    name = "discovery_cache"
    description = "Retrieves pre-collected recon findings (DNS, WHOIS, SSL, IP, headers) from the discovery cache file."
    parameters = {"query": "Optional: specific key to retrieve (e.g., 'dns', 'whois', 'ssl', 'ip', 'headers', 'page'). If empty, returns all cached data."}

    def execute(self, query: str = "", **kwargs) -> str:
        cache_path = "/tmp/discovery_cache.json"
        if not os.path.exists(cache_path):
            return "No discovery cache found. Run InitialDiscovery first."
        
        try:
            with open(cache_path, "r") as f:
                data = json.load(f)
            
            if query:
                q_clean = str(query).lower().strip()
                if q_clean in data:
                    return json.dumps(data[q_clean], indent=2)
                return f"Key '{query}' not found. Available: {list(data.keys())}"
            
            return json.dumps(data, indent=2)
        except Exception as e:
            return f"Error reading discovery cache: {str(e)}"
