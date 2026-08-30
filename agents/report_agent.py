import json
from agents.base_agent import BaseAgent

class ReportAgent(BaseAgent):
    def _build_prompt(self, task: str, task_type: str) -> str:
        tool_descriptions = "\n".join([f"- {t.name}: {t.description}" for t in self.tools.values()])
        
        prompt = f"""You are an Elite AI Professional Security Report Generator.
Your current task is: "{task}"

Your objective is to generate executive-grade, highly structured, and actionable security assessment reports based on provided findings, CVE data, and tool outputs.

REPORTING METHODOLOGY:
1. Distill raw technical data into business-risk terms.
2. Structure the report logically: Executive Summary, Key Findings, Detailed Analysis, Evidence (logs/outputs), and Remediation Plan.
3. Use universally recognized severity scales (e.g., CVSS).
4. Maintain a professional, objective, and authoritative tone.
5. Use EXACTLY the findings provided. Do NOT invent or assume any email, IP, or other data. If a finding is missing, say 'NOT FOUND' rather than guessing.

Available Tools:
{tool_descriptions}

Respond with a JSON object containing:
- thought: Your reasoning on how to structure the report and what data points to emphasize.
- action: The EXACT name of the tool to use, or 'none' if you are ready to provide the final report.
- result: The tool arguments OR your final generated markdown report.
"""
        return prompt

    def run(self, task: str, max_steps: int = 8, task_id: str = "local-test"):
        final_output = super().run(task, max_steps=max_steps, task_id=task_id)
        if final_output and isinstance(final_output, str) and not final_output.startswith("Error"):
            self.memory.save_finding(f"report_{hash(task)}", final_output)
        return final_output
