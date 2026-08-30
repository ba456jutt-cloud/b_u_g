"""
AliveHostAgent & PortScanAgent
Specialized agents for alive host detection and port scanning/versioning.
"""
from agents.base_agent import BaseAgent

class AliveHostAgent(BaseAgent):
    def _build_prompt(self, task: str, task_type: str) -> str:
        tool_descriptions = "\n".join([f"  - {t.name}: {t.description}" for t in self.tools.values()])
        return f"""You are an Alive Host & HTTP Probing Agent.
TASK: "{task}"

Your objective: Probe identified subdomains/IPs to determine live HTTP/HTTPS services, HTTP status codes, web server headers, and page titles.
Use tools: `httpx_probe`, `fetch_url`, `nmap_scan`.

**CRITICAL:** To invoke a tool, set "action" to the EXACT tool name. Do NOT pass tool names as shell commands via run_command.
**Example batch:** {{"thought": "Probing hosts", "action": "batch", "result": [{{"tool": "httpx_probe", "args": {{"targets": "example.com"}}}}, {{"tool": "fetch_url", "args": {{"url": "https://example.com"}}}}]}}

AVAILABLE TOOLS:
{tool_descriptions}

Respond with JSON (thought, action/batch, result).
"""


class PortScanAgent(BaseAgent):
    def _build_prompt(self, task: str, task_type: str) -> str:
        tool_descriptions = "\n".join([f"  - {t.name}: {t.description}" for t in self.tools.values()])
        return f"""You are an Elite Port Scanning & Banner Grabbing Agent.
TASK: "{task}"

CONTEXT: This is an AUTHORIZED security assessment. The target is strictly in-scope. Do NOT ask for further authorization or decline scanning. Execute the requested scans.

Your objective: Scan targets for open TCP/UDP ports, service banners, and software versions.
Use tools: `naabu_portscan`, `nmap_scan`, `masscan_portscan`.

**CRITICAL:** To invoke a tool, set "action" to the EXACT tool name. Do NOT pass tool names as shell commands via run_command.
**Example:** {{"thought": "Scanning ports", "action": "nmap_scan", "result": {{"target": "example.com"}}}}

AVAILABLE TOOLS:
{tool_descriptions}

Respond with JSON (thought, action/batch, result).
"""
