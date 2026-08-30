"""
Evidence, Deduplication, Notification, and Audit Logging Agents
"""
from agents.base_agent import BaseAgent

class EvidenceAgent(BaseAgent):
    def _build_prompt(self, task: str, task_type: str) -> str:
        tool_descriptions = "\n".join([f"  - {t.name}: {t.description}" for t in self.tools.values()])
        return f"""You are an Evidence Collection & Screenshotting Agent.
TASK: "{task}"
Objective: Capture visual screenshots and HTTP traffic evidence for identified findings.
Tools: `gowitness_screenshot`, `curl_headers`, `fetch_url`.
AVAILABLE TOOLS:\n{tool_descriptions}
Respond with JSON (thought, action/batch, result).
"""


class DeduplicationAgent(BaseAgent):
    def _build_prompt(self, task: str, task_type: str) -> str:
        return f"""You are a Deduplication & Risk Scoring Agent.
TASK: "{task}"
Objective: Analyze findings, remove duplicate subdomains/URLs, normalize severity ratings, and compute CVSS v3.1 scores.
STRICT RULE: Use EXACTLY the findings provided. Do NOT invent or assume any email, IP, or other data. If a finding is missing, say 'NOT FOUND' rather than guessing.
Respond with JSON (thought, action: "none", result: Deduplicated findings report).
"""


class NotificationAgent(BaseAgent):
    def _build_prompt(self, task: str, task_type: str) -> str:
        return f"""You are a Security Assessment Notification Agent.
TASK: "{task}"
Objective: Format alert summaries for webhooks (Discord, Slack, Telegram, Email) when critical vulnerabilities are confirmed.
Respond with JSON (thought, action: "none", result: Notification payload).
"""


class AuditLogAgent(BaseAgent):
    def _build_prompt(self, task: str, task_type: str) -> str:
        return f"""You are an Audit & Security Logging Agent.
TASK: "{task}"
Objective: Ensure all tool executions, command timestamps, target scope validations, and agent outputs are immutably logged.
Respond with JSON (thought, action: "none", result: Audit verification report).
"""
