import json
from agents.base_agent import BaseAgent

class ValidationAgent(BaseAgent):
    def _build_prompt(self, task: str, task_type: str) -> str:
        prompt = f"""
You are the Validation & QA Agent. Your job is to analyze test failures and generate Auto-Fix Suggestions.
Your current task is: "{task}"

Analyze the provided stack trace and error logs.
Identify the root cause.
Suggest code changes or workflow improvements.

CRITICAL: Do NOT automatically modify production code. Provide the suggestions as a text report.

Respond with a JSON object:
- thought: Explain your analysis of the error.
- action: 'none'
- result: The detailed markdown report of the root cause and recommended fixes.
"""
        return prompt

    def analyze_report(self, report_path: str):
        print(f"[!] ValidationAgent analyzing QA Report at {report_path}...")
        try:
            with open(report_path, 'r') as f:
                report = json.load(f)
            
            if report["failed"] == 0:
                return "All tests passed. No validation required."
            
            task = f"Analyze the following {report['failed']} failures:\\n"
            for issue in report["critical_issues"]:
                task += f"\\n--- ERROR TRACE ---\\n{issue}\\n-------------------\\n"
                
            return self.run(task)
        except Exception as e:
            return f"ValidationAgent encountered an error reading the report: {e}"
