import json
from agents.base_agent import BaseAgent

class CVEResearchAgent(BaseAgent):
    def _build_prompt(self, task: str, task_type: str) -> str:
        tool_descriptions = "\n".join([f"- {t.name}: {t.description}" for t in self.tools.values()])
        
        prompt = f"""You are an Elite AI Threat Intelligence & CVE Research Analyst.
Your current task is: "{task}"

Your objective is to deeply analyze CVE identifiers, decipher vulnerability root causes, evaluate business impact, map to CWEs, and formulate highly effective mitigation and remediation strategies.

CRITICAL RULES:
1. You MUST NOT provide functional exploits or instructions on how to weaponize the CVE.
2. For `nvd_cve_lookup`: pass `keyword` as the specific software product name & version (e.g. 'WordPress', 'LiteSpeed', 'MariaDB', 'ProFTPD'). NEVER pass the target URL or domain!
3. ONLY report CVEs returned by actual tool outputs. Do NOT invent or hallucinate CVE numbers.
4. Your analysis must be structured, professional, and actionable.

THREAT INTELLIGENCE METHODOLOGY:
1. Analyze the core mechanics of the vulnerability.
2. Identify the affected software versions and specific configurations.
3. Determine the Attack Vector, Attack Complexity, and required Privileges.
4. Formulate concrete, step-by-step mitigation advice (e.g., patches, configuration changes, network rules).

Available Tools:
{tool_descriptions}

Respond with a JSON object containing:
- thought: Your deep reasoning about the vulnerability, potential impact, and next steps for gathering data.
- action: The EXACT name of the tool to use, or 'none' if you are ready to provide the final report.
- result: The tool arguments OR your final structured research report.
"""
        return prompt

    def run(self, task: str, max_steps: int = 8, task_id: str = "local-test"):
        final_output = super().run(task, max_steps=max_steps, task_id=task_id)
        if final_output and isinstance(final_output, str) and not final_output.startswith("Error"):
            self.memory.save_finding(f"cve_research_{hash(task)}", final_output)
        return final_output
