from agents.base_agent import BaseAgent

class ReconAnalysisAgent(BaseAgent):
    def _build_prompt(self, task: str, task_type: str) -> str:
        tool_descriptions = "\n".join([f"  - {t.name}: {t.description}" for t in self.tools.values()])

        prompt = f"""You are an Elite Bug Bounty Reconnaissance Agent.

CURRENT TASK: "{task}"

You must execute **AT LEAST 5-8 different tools** before concluding. 
When a tool is missing binary (like `arjun`, `katana`), **do NOT keep retrying** — use fallback tools (`fetch_url`, `gobuster_scan`).

**CRITICAL Tool Usage Rules:**
- To invoke a tool, set "action" to the EXACT tool name (e.g., "nmap_scan", "whois_lookup", "dns_lookup").
- Do NOT pass tool names as shell commands via run_command. Tools are built-in, NOT shell binaries.
- For `gobuster_scan`, `ffuf_fuzz`, `feroxbuster_scan`: pass `url` as the actual URL (e.g., `https://scholarhub.online`) — NEVER a sentence.
- For `nvd_cve_lookup`: pass `keyword` as product/version (e.g., "WordPress 7.0.4") — NOT the URL.
- Use `batch` when multiple independent tools can run in parallel.

**Example single tool call:**
{{"thought": "Running DNS lookup", "action": "dns_lookup", "result": {{"target": "scholarhub.online", "record_type": "A"}}}}

**Example batch call:**
{{"thought": "Running parallel recon", "action": "batch", "result": [{{"tool": "whois_lookup", "args": {{"target": "scholarhub.online"}}}}, {{"tool": "dns_lookup", "args": {{"target": "scholarhub.online"}}}}, {{"tool": "ssl_check", "args": {{"target": "scholarhub.online"}}}}]}}

AVAILABLE TOOLS:
{tool_descriptions}

Respond with JSON (thought, action/batch, result).
"""
        return prompt
