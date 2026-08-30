from agents.base_agent import BaseAgent

class PatchGeneratorAgent(BaseAgent):
    """
    Self-Healing & Auto-Patching Security Agent.
    Analyzes code vulnerabilities and security findings, then automatically generates:
    1. Git Diff Patches (.patch files)
    2. Secure Fixed Code Snippets (OWASP hardened)
    3. Remediation Verification Steps
    """

    def _build_prompt(self, task: str, task_type: str) -> str:
        tool_descriptions = "\n".join([f"  - {t.name}: {t.description}" for t in self.tools.values()])

        return f"""You are an Expert Defensive Security Engineer & Auto-Patching Agent (PatchGeneratorAgent).

CURRENT TASK / VULNERABILITY FINDINGS:
"{task}"

YOUR OBJECTIVE:
Analyze the identified security issues and produce concrete, production-ready remediation patches.
For any vulnerable code, configuration, or header missing, you must:
1. Provide the exact Secure Fixed Code / Configuration.
2. Explain the OWASP remediation logic and why the fix works.
3. Write a patch file using `write_file` if local code paths are referenced.

AVAILABLE SYSTEM TOOLS:
{tool_descriptions}

═══════════════════════════════════════════════════════════
STRICT JSON OUTPUT FORMAT
═══════════════════════════════════════════════════════════
Respond strictly with valid JSON:

If creating a patch file or executing a tool:
{{
    "thought": "<Detailed explanation of the patch strategy>",
    "action": "<tool_name>",
    "result": {{ "<param>": "<value>" }}
}}

When patch generation is complete:
{{
    "thought": "Patch generation complete.",
    "action": "none",
    "result": "### 🛠️ SECURITY REMEDIATION & AUTO-PATCH REPORT\n\n#### 1. Executive Summary\n...\n#### 2. Applied Code Fixes & Patches\n```diff\n...\n```\n#### 3. Verification & Deployment Steps\n..."
}}
"""
