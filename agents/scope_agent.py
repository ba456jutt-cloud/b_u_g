"""
ScopeManagementAgent — Validates target against allowed scope, wildcards, blacklists, and rules.
Ensures no unauthorized security scanning takes place outside approved boundaries.
"""
import re
from agents.base_agent import BaseAgent

class ScopeManagementAgent(BaseAgent):
    def validate_scope(self, target: str, allowed_rules: list, out_of_scope_rules: list) -> dict:
        """Validates if a target domain/IP is within allowed scope."""
        clean_target = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

        # Check out-of-scope blacklists first
        for oos in out_of_scope_rules:
            clean_oos = oos.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
            pattern = "^" + re.escape(clean_oos).replace(r"\*", ".*") + "$"
            if re.match(pattern, clean_target):
                return {
                    "allowed": False,
                    "target": clean_target,
                    "reason": f"Target '{clean_target}' matches out-of-scope rule '{oos}'"
                }

        # Check allowed scope
        if not allowed_rules:
            return {"allowed": True, "target": clean_target, "note": "Wildcard/No restriction"}

        for allowed in allowed_rules:
            clean_allowed = allowed.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
            pattern = "^" + re.escape(clean_allowed).replace(r"\*", ".*") + "$"
            if re.match(pattern, clean_target):
                return {"allowed": True, "target": clean_target, "matched_rule": allowed}

        return {
            "allowed": False,
            "target": clean_target,
            "reason": f"Target '{clean_target}' not explicitly in allowed scope list: {allowed_rules}"
        }

    def _build_prompt(self, task: str, task_type: str) -> str:
        prompt = f"""You are the Scope Management & Program Rules Compliance Officer.
CURRENT TASK: "{task}"

Analyze the target and scope parameters:
1. Verify if the target domain/IP is within explicitly authorized boundaries.
2. Check for wildcard scope allowances (*.domain.com).
3. Identify strictly prohibited out-of-scope assets or rate-limit guidelines.
4. Output a clear JSON verification status.

Respond with JSON containing:
- thought: Scope compliance analysis
- action: "none"
- result: Scope validation verdict with allowed/disallowed status and guidelines.
"""
        return prompt
