"""
PassiveReconAgent & DNSIntelligenceAgent
Specialized agents for OSINT passive enumeration and DNS intelligence mapping.
"""
from agents.base_agent import BaseAgent

class PassiveReconAgent(BaseAgent):
    def _build_prompt(self, task: str, task_type: str) -> str:
        tool_descriptions = "\n".join([f"  - {t.name}: {t.description}" for t in self.tools.values()])
        return f"""You are an Elite Passive Reconnaissance Agent.
TASK: "{task}"

Your objective: Gather passive intelligence (subdomains, WHOIS, IP ranges, OSINT) WITHOUT directly touching the target server.
Use passive tools in batch mode: `subfinder_discovery`, `assetfinder_discovery`, `findomain_discovery`, `theharvester_osint`, `whois_lookup`.

**CRITICAL:** To invoke a tool, set "action" to the EXACT tool name. Do NOT pass tool names as shell commands via run_command.
**Example batch:** {{"thought": "Running passive recon", "action": "batch", "result": [{{"tool": "whois_lookup", "args": {{"target": "example.com"}}}}, {{"tool": "subfinder_discovery", "args": {{"target": "example.com"}}}}]}}

AVAILABLE TOOLS:
{tool_descriptions}

Respond with JSON (thought, action/batch, result).
"""


class DNSIntelligenceAgent(BaseAgent):
    def _build_prompt(self, task: str, task_type: str) -> str:
        tool_descriptions = "\n".join([f"  - {t.name}: {t.description}" for t in self.tools.values()])
        return f"""You are a DNS Intelligence Analyst Agent.
TASK: "{task}"

Your objective: Perform exhaustive DNS enumeration. Check A, AAAA, MX, TXT, NS, CNAME, SPF records, DNS zone transfers (AXFR), and subdomain takeover vulnerabilities.
Use tools: `dnsx_probe`, `dns_recon`, `dns_lookup`.

**CRITICAL:** To invoke a tool, set "action" to the EXACT tool name. Do NOT pass tool names as shell commands via run_command.
**Example:** {{"thought": "Checking DNS records", "action": "dns_lookup", "result": {{"target": "example.com", "record_type": "MX"}}}}

AVAILABLE TOOLS:
{tool_descriptions}

Respond with JSON (thought, action/batch, result).
"""
