import re
from agents.base_agent import BaseAgent

class ReconAnalysisAgent(BaseAgent):
    @staticmethod
    def _extract_target(task: str) -> str:
        """Extract the target domain/URL from the task string for use in prompt examples."""
        url_match = re.search(r'https?://[\w./-]+', task)
        if url_match:
            return url_match.group(0).rstrip('/')
        domain_match = re.search(r'([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}', task)
        if domain_match:
            return f"https://{domain_match.group(0)}"
        return "https://target.example.com"

    def _build_prompt(self, task: str, task_type: str) -> str:
        tool_descriptions = "\n".join([f"  - {t.name}: {t.description}" for t in self.tools.values()])
        # Dynamic target from task — no hardcoded domains in prompt
        target = self._extract_target(task)
        target_domain = target.replace("https://", "").replace("http://", "").split("/")[0]

        prompt = f"""You are an Elite Bug Bounty Reconnaissance Agent.

CURRENT TASK: "{task}"

Use as many tools as needed to fully recon the target. Stop when you have sufficient findings.
When a tool is missing binary (like `arjun`, `katana`), **do NOT keep retrying** — use fallback tools (`fetch_url`, `gobuster_scan`).

**CRITICAL Tool Usage Rules:**
- To invoke a tool, set "action" to the EXACT tool name (e.g., "nmap_scan", "whois_lookup", "dns_lookup").
- Do NOT pass tool names as shell commands via run_command. Tools are built-in, NOT shell binaries.
- For `gobuster_scan`, `ffuf_fuzz`, `feroxbuster_scan`: pass `url` as the actual URL (e.g., `{target}`) — NEVER a sentence.
- For `nvd_cve_lookup`: pass `keyword` as product/version (e.g., "WordPress 7.0.4") — NOT the URL.
- Use `batch` when multiple independent tools can run in parallel.

**Example single tool call:**
{{"thought": "Running DNS lookup", "action": "dns_lookup", "result": {{"target": "{target_domain}", "record_type": "A"}}}}

**Example batch call:**
{{"thought": "Running parallel recon", "action": "batch", "result": [{{"tool": "whois_lookup", "args": {{"target": "{target_domain}"}}}}, {{"tool": "dns_lookup", "args": {{"target": "{target_domain}"}}}}, {{"tool": "ssl_check", "args": {{"target": "{target_domain}"}}}}]}}

AVAILABLE TOOLS:
{tool_descriptions}

Respond with JSON (thought, action/batch, result).
"""
        return prompt
