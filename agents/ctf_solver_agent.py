import json
import hashlib
from agents.base_agent import BaseAgent

class CTFSolverAgent(BaseAgent):
    """
    Specialized CTF (Capture The Flag) Competition Solver Agent.
    
    Capabilities:
      1. Auto-detects CTF flags (flag{...}, CTF{...}, picoCTF{...}, HTB{...}, etc.).
      2. Decodes complex ciphers: Base64, Hex, ROT13, JWT tokens, URL encoding, XOR brute-force.
      3. Automates Web CTF challenges: robots.txt, HTML comments, .git exposures, cookie tampering, auth bypass.
      4. Inspects binary files & images for hidden stego payloads and EXIF metadata.
      5. Solves challenges step-by-step and produces structured CTF Writeups.
    """

    def _build_prompt(self, task: str, task_type: str) -> str:
        tool_descriptions = "\n".join([f"  - {t.name}: {t.description}" for t in self.tools.values()])
        reflections_str = self._get_reflections_prompt_block()
        perf_str = self._get_performance_score_prompt_block()
        findings_str = self._get_findings_prompt_block()

        prompt = f"""You are an Elite World-Class CTF Player & Reverse Engineering Expert (CTFSolverAgent).

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CURRENT CTF CHALLENGE:
"{task}"
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{perf_str}
{findings_str}

YOUR OBJECTIVE:
Solve the CTF challenge, find and extract the FLAG, and provide the exact solution methodology.

SOLVER METHODOLOGY (FAST PARALLEL EXECUTION):
1. STEP 1 PARALLEL BATCHING (CRITICAL FOR TOKEN EFFICIENCY):
   - On Step 1, YOU ALREADY KNOW what tools will be needed! Execute ALL initial recon and solver tools IN A SINGLE PARALLEL STEP!
   - Use `action: "batch"` and list: `web_ctf_solver`, `crypto_decoder`, `stego_forensics`, and `flag_scanner` together!
   - The system executes all tools in parallel and returns all responses in 1 step!

2. ITERATE & DECODE:
   - If a multi-stage cipher is found (e.g. Base64 inside Hex inside ROT13), run `crypto_decoder` repeatedly.
   - If a web login is required, test SQLi auth bypass (`' OR '1'='1`) or cookie decode.

3. CONFIRM & REPORT:
   - Once the flag `flag{{...}}` is found, highlight it clearly and write the final CTF writeup.

AVAILABLE SYSTEM TOOLS:
{tool_descriptions}

{reflections_str}

═══════════════════════════════════════════════════════════
STRICT JSON OUTPUT PROTOCOL (PARALLEL & SINGLE TOOL)
═══════════════════════════════════════════════════════════
Respond strictly with valid JSON:

FOR STEP 1 PARALLEL BATCHING (RECOMMENDED):
{{
    "thought": "Running initial CTF reconnaissance & solver battery in parallel to save time and API quota.",
    "action": "batch",
    "result": [
        {{ "tool": "web_ctf_solver", "args": {{ "target_url": "<url>" }} }},
        {{ "tool": "crypto_decoder", "args": {{ "ciphertext": "<task_string>", "operation": "auto" }} }},
        {{ "tool": "flag_scanner", "args": {{ "text": "<task_string>" }} }}
    ]
}}

For single tool execution:
{{
    "thought": "<Detailed CTF step reasoning>",
    "action": "<tool_name>",
    "result": {{ "<param1>": "<val1>" }}
}}

    "action": "<tool_name>",
    "result": {{ "<param1>": "<val1>", "<param2>": "<val2>" }}
}}

When completed and FLAG IS FOUND:
{{
    "thought": "CTF challenge solved! Flag extracted successfully.",
    "action": "none",
    "result": "### 🚩 CTF CHALLENGE SOLUTION & WRITEUP\\n\\n#### Challenge Name\\n<task_name>\\n\\n#### DISCOVERED FLAG\\n```\\n<exact_flag_here>\\n```\\n\\n#### Step-by-Step Solution Methodology\\n1. <Step 1>\\n2. <Step 2>\\n\\n#### Tools & Decoders Used\\n<tools_used>\\n\\n#### Vulnerability / Challenge Category\\n<Web / Crypto / Stego / Reverse Engineering / Misc>"
}}
"""
        return prompt

    def run(self, task: str, max_steps: int = 8, task_id: str = "local-test"):
        final_output = super().run(task, max_steps=max_steps, task_id=task_id)
        if final_output and isinstance(final_output, str) and not final_output.startswith("Error"):
            self.memory.save_finding(f"ctf_flag_{hashlib.sha256(task.encode()).hexdigest()[:16]}", final_output, task_id=task_id)
        return final_output
