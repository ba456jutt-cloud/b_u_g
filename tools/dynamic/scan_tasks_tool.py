from tools.base import Tool
import subprocess
import requests
from typing import List, Dict, Any

class ScanTasksTool(Tool):
    name = "scan_tasks"
    description = "Performs multiple security tasks against a target, including fetching sitemaps, robots.txt, specific URLs, and running scans like Nmap and Nuclei."
    parameters = {"tasks": "List of tasks to perform"}

    def execute(self, tasks: List[Dict[str, Any]], **kwargs) -> str:
        results = {}
        
        for task in tasks:
            task_type = task['task']
            target = task.get('target', '')
            args = task.get('args', '')
            
            try:
                if task_type == 'sitemap_fetch':
                    results['sitemap_fetch'] = self.fetch_sitemap(target)
                elif task_type == 'robots_txt_fetch':
                    results['robots_txt_fetch'] = self.fetch_robots_txt(target)
                elif task_type == 'fetch_url':
                    results['fetch_url'] = self.fetch_url(target)
                elif task_type == 'nmap_scan':
                    results['nmap_scan'] = self.run_nmap_scan(target, args)
                elif task_type == 'nuclei_scan':
                    results['nuclei_scan'] = self.run_nuclei_scan(target, args)
                else:
                    results[task_type] = f"Unknown task type: {task_type}"
            except Exception as e:
                results[task_type] = f"Error executing {task_type}: {str(e)}"
        
        return str(results)

    def fetch_sitemap(self, target: str) -> str:
        try:
            resp = requests.get(f"{target}/sitemap.xml", timeout=10, verify=False)
            return f"HTTP {resp.status_code}\nHeaders: {dict(resp.headers)}\nBody Snippet: {resp.text[:1000]}"
        except Exception as e:
            return f"[ERROR] Request failed: {str(e)}"

    def fetch_robots_txt(self, target: str) -> str:
        try:
            resp = requests.get(f"{target}/robots.txt", timeout=10, verify=False)
            return f"HTTP {resp.status_code}\nHeaders: {dict(resp.headers)}\nBody Snippet: {resp.text[:1000]}"
        except Exception as e:
            return f"[ERROR] Request failed: {str(e)}"

    def fetch_url(self, url: str) -> str:
        try:
            resp = requests.get(url, timeout=10, verify=False)
            return f"HTTP {resp.status_code}\nHeaders: {dict(resp.headers)}\nBody Snippet: {resp.text[:1000]}"
        except Exception as e:
            return f"[ERROR] Request failed: {str(e)}"

    def run_nmap_scan(self, target: str, args: str) -> str:
        cmd = ["nmap"] + args.split() + [target]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout if result.returncode == 0 else f"Error: {result.stderr}"

    def run_nuclei_scan(self, target: str, args: str) -> str:
        cmd = ["nuclei"] + args.split() + [target]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout if result.returncode == 0 else f"Error: {result.stderr}"