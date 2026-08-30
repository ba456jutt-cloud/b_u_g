import os
import re
import importlib.util
from agents.base_agent import BaseAgent
from tools.validation import ToolValidator

# Read an existing tool as a reference example
_NMAP_EXAMPLE = """
from tools.base import Tool
import subprocess

class NmapScanTool(Tool):
    name = "nmap_scan"
    description = "Runs an Nmap port scan against a target."
    parameters = {"target": "IP or hostname", "flags": "Nmap flags string"}

    def execute(self, target: str, flags: str = "-T4 -F", **kwargs) -> str:
        cmd = ["nmap"] + flags.split() + [target]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout if result.returncode == 0 else f"Error: {result.stderr}"
"""

_FETCH_EXAMPLE = """
from tools.base import Tool
import requests

class FetchURLTool(Tool):
    name = "fetch_url"
    description = "Fetches HTTP response headers and body from a target URL safely."
    parameters = {"url": "Target URL to inspect"}

    def execute(self, url: str = None, target: str = None, **kwargs) -> str:
        target_url = url or target or kwargs.get('domain') or kwargs.get('host') or "http://127.0.0.1"
        try:
            resp = requests.get(target_url, timeout=10, verify=False)
            return f"HTTP {resp.status_code}\nHeaders: {dict(resp.headers)}\nBody Snippet: {resp.text[:1000]}"
        except Exception as e:
            return f"[ERROR] Request failed: {str(e)}"
"""



class GeneralToolBuilderAgent(BaseAgent):

    def _build_prompt(self, task: str, task_type: str) -> str:
        existing_tools = list(self.tools.keys())
        tool_list_str = "\n".join(f"  - {t}" for t in existing_tools)

        prompt = f"""You are an elite Security Tool Builder Agent and Exploit Developer. You write professional, robust, and highly advanced Python security tools and exploit PoCs.

CURRENT REQUEST: "{task}"

EXISTING TOOLS (do NOT re-create these):
{tool_list_str}

YOUR TASK:
Analyze the request with deep security reasoning. Generate a complete, working Python Tool class that fulfills the request, which may involve vulnerability scanning, exploitation, or data exfiltration.

STRICT REQUIREMENTS:
1. The class MUST inherit from `tools.base.Tool`
2. MUST have these class attributes: `name` (str), `description` (str), `parameters` (dict)
3. MUST implement `execute(self, **kwargs) -> str` method
4. The `name` attribute must be unique, snake_case, and descriptive (e.g. `cve_2024_xxxx_exploit`)
5. MUST handle all exceptions gracefully and return detailed error messages as strings (never raise unhandled exceptions)
6. MUST include timeout handling for network operations to prevent hanging
7. Allowed network modules: `subprocess`, `socket`, `urllib`, `requests`, `http`
8. Return valid JSON containing your reasoning and the complete Python code:
{{
    "thought": "<Detailed security reasoning on tool architecture and parameters>",
    "action": "none",
    "result": "<COMPLETE WORKING PYTHON TOOL CODE HERE>"
}}


REFERENCE EXAMPLES (study these patterns):

Example 1 - Subprocess-based tool:
{_NMAP_EXAMPLE}

Example 2 - Network tool:
{_FETCH_EXAMPLE}

Now generate the tool. Return ONLY the JSON object.
"""

        return prompt

    def run(self, task: str, max_steps: int = 8, task_id: str = "local-test"):
        print("[!] ToolBuilderAgent: Analyzing security capability gap...")
        self.memory.log_execution(task_id, self.__class__.__name__, "System",
                                  f"ToolBuilderAgent started for task: {task}")

        # === STEP 1: Check if tool already exists ===
        existing_tools = list(self.tools.keys())
        self.memory.log_execution(task_id, self.__class__.__name__, "Thought",
                                  f"Existing tools: {existing_tools}. Analyzing if a new tool is needed...")

        # === STEP 2: Generate tool code via LLM ===
        self.memory.log_execution(task_id, self.__class__.__name__, "Action",
                                  "Calling LLM to generate new security tool code...")
        task_type = self.router.route(task) if (hasattr(self.router, "route") and callable(getattr(self.router, "route"))) else "ToolBuilder"

        prompt = self._build_prompt(task, task_type)
        llm_response = self.llm.generate(prompt)

        thought = llm_response.get("thought", "No reasoning provided")
        self.memory.log_execution(task_id, self.__class__.__name__, "Thought",
                                  f"LLM Reasoning:\n{thought}")

        # Extract the generated code cleanly from markdown blocks or class definition
        raw_result = str(llm_response.get("result", ""))
        
        # Regex search for ```python ... ``` or ``` ... ```
        code_match = re.search(r"```(?:python)?\s*(.*?)\s*```", raw_result, re.DOTALL | re.IGNORECASE)
        if code_match:
            generated_code = code_match.group(1).strip()
        else:
            # Fallback search for 'class ...' or 'from ...' or 'import ...' start
            class_match = re.search(r"((?:from|import|class)\s+[A-Za-z0-9_]+.*)", raw_result, re.DOTALL)
            if class_match:
                generated_code = class_match.group(1).strip()
            else:
                generated_code = raw_result.strip()



        if not generated_code or len(generated_code) < 50:
            error = f"Tool creation failed: LLM returned insufficient code (length: {len(generated_code)})"
            self.memory.log_execution(task_id, self.__class__.__name__, "Error", error)
            return error

        self.memory.log_execution(task_id, self.__class__.__name__, "Result",
                                  f"Generated code ({len(generated_code)} chars):\n{generated_code}")

        # === STEP 3: AST Validation ===
        self.memory.log_execution(task_id, self.__class__.__name__, "Action",
                                  "Running AST security validation on generated code...")
        violations = ToolValidator.validate_code(generated_code, allow_security_modules=True)

        if violations:
            error_msg = f"AST Validation FAILED:\n" + "\n".join(f"  - {v}" for v in violations)
            self.memory.log_execution(task_id, self.__class__.__name__, "Error", error_msg)

            # Try to auto-fix: ask LLM to fix the violations
            self.memory.log_execution(task_id, self.__class__.__name__, "Action",
                                      "Attempting to auto-fix violations by re-prompting LLM...")
            fix_prompt = f"""The following Python code has security violations:

VIOLATIONS:
{chr(10).join(violations)}

ORIGINAL CODE:
{generated_code}

Fix the violations while keeping all functionality intact. Return ONLY the fixed Python code, no markdown."""

            fix_response = self.llm.generate(fix_prompt)
            fixed_code = fix_response.get("result", "")
            fixed_code = re.sub(r"```python\s*", "", fixed_code)
            fixed_code = re.sub(r"```\s*", "", fixed_code).strip()

            second_check = ToolValidator.validate_code(fixed_code, allow_security_modules=True)
            if second_check:
                final_error = f"Auto-fix failed. Violations remain: {second_check}"
                self.memory.log_execution(task_id, self.__class__.__name__, "Error", final_error)
                return final_error
            else:
                generated_code = fixed_code
                self.memory.log_execution(task_id, self.__class__.__name__, "System",
                                          "Auto-fix succeeded! Violations cleared.")

        # === STEP 4: Syntax + Import test ===
        try:
            compile(generated_code, "<generated_tool>", "exec")
            self.memory.log_execution(task_id, self.__class__.__name__, "System",
                                      "Code compiled successfully. Syntax check passed.")
        except SyntaxError as e:
            error = f"Syntax error in generated code: {e}"
            self.memory.log_execution(task_id, self.__class__.__name__, "Error", error)
            return error

        # === STEP 5: Extract tool name and save ===
        tool_class_name = ToolValidator.extract_class_name(generated_code)
        tool_file_name = re.sub(r'(?<!^)(?=[A-Z])', '_', tool_class_name).lower().replace("__", "_") + "_tool.py"
        # Clean up name
        tool_file_name = tool_file_name.replace("_tool_tool", "_tool")

        tools_dir = os.path.join(os.getcwd(), "tools", "dynamic")
        os.makedirs(tools_dir, exist_ok=True)
        file_path = os.path.join(tools_dir, tool_file_name)

        try:
            # Add base import if missing
            if "from tools.base import Tool" not in generated_code and "tools.base" not in generated_code:
                generated_code = "from tools.base import Tool\n\n" + generated_code

            with open(file_path, "w") as f:
                f.write(generated_code)

            self.memory.log_execution(task_id, self.__class__.__name__, "Result",
                                      f"Tool saved to: {file_path}")

            # === STEP 6: Dynamic loading test ===
            spec = importlib.util.spec_from_file_location(tool_class_name, file_path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            tool_class = getattr(mod, tool_class_name, None)

            if tool_class:
                # Register in live registry
                from tools.registry import registry
                instance = tool_class()
                registry.register_tool(instance)

                success = (
                    f"✅ NEW TOOL CREATED AND LIVE-LOADED!\n"
                    f"  Class: {tool_class_name}\n"
                    f"  Name: {instance.name}\n"
                    f"  Description: {instance.description}\n"
                    f"  File: {file_path}\n"
                    f"  Status: Available NOW in this session (no restart needed!)"
                )
                self.memory.log_execution(task_id, self.__class__.__name__, "Result", success)
                return success
            else:
                warn = f"Tool saved to {file_path} but could not auto-load class '{tool_class_name}'. Restart backend to use it."
                self.memory.log_execution(task_id, self.__class__.__name__, "Result", warn)
                return warn

        except Exception as e:
            err = f"Error saving/loading tool: {str(e)}"
            self.memory.log_execution(task_id, self.__class__.__name__, "Error", err)
            return err
