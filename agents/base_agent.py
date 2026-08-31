import json
import os
import subprocess
import re
import inspect
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from core.llm_provider import LLMProvider
from memory.sqlite_mem import MemoryDB
from router.task_router import TaskRouter
from tools.base import Tool
from typing import List, Dict, Optional

class BaseAgent:
    """
    Adaptive, Self-Healing & Parallel ReAct Agent Loop — FUGU & Mythos Inspired.
    Fully fixed: robust target extraction, alias mapping, OSError handling, loop detection.
    """

    PARAM_BLACKLIST = frozenset({
        "target", "ports", "flags", "scan_type", "arguments", "options",
        "host", "ip", "protocol", "url", "domain", "output", "format",
        "timeout", "method", "data", "headers", "cookies", "thought",
        "explanation", "analysis", "result", "action", "args", "parameters",
        "description", "name", "type", "value", "input", "query", "path",
        "port", "service", "version", "severity", "risk", "level",
        "username", "password", "token", "key", "secret", "body",
        "response", "status", "code", "message", "error", "warning",
        "note", "comment", "tag", "label", "category", "priority",
        "tool", "tools", "command", "commands", "cmd", "script", "operation", "operations"
    })

    def __init__(self, llm_provider: LLMProvider, memory: MemoryDB, router: TaskRouter, tools: List[Tool]):
        self.llm = llm_provider
        self.memory = memory
        self.router = router
        self.tools = {tool.name: tool for tool in tools}
        self._consecutive_failures = 0

    def _safe_print(self, msg: str):
        """Print that won't crash if terminal is disconnected (Errno 5)."""
        try:
            print(msg, flush=True)
        except (IOError, OSError):
            pass

    def _emit(self, event_type: str, **kwargs):
        try:
            publisher = getattr(__builtins__, '_publish_activity', None)
            if publisher is None and hasattr(__builtins__, '__dict__'):
                publisher = __builtins__.__dict__.get('_publish_activity')
            if publisher:
                publisher(event_type, agent=self.__class__.__name__, **kwargs)
        except Exception:
            pass

    def _get_reflections_prompt_block(self) -> str:
        reflections = self.memory.get_reflections(self.__class__.__name__, limit=4)
        if not reflections:
            return ""
        ref_items = []
        for r in reflections:
            ref_items.append(f"  - Failed Action: {r['failed_action']}\n    Error: {r['error_output']}\n    Lesson: {r['lesson']}")
        return "\n═══════════════════════════════════════════════════════════\nPAST FAILURES & LEARNED LESSONS (SELF-LEARNING MEMORY)\n═══════════════════════════════════════════════════════════\n" + "\n".join(ref_items) + "\n"

    def _get_performance_score_prompt_block(self) -> str:
        perf = self.memory.get_agent_performance_score(self.__class__.__name__)
        score = perf["total_score"]
        eff = perf["efficiency_rate"]
        succ = perf["success_actions"]
        pen = perf["penalties"]
        score_str = f"+{score}" if score >= 0 else str(score)
        return f"CURRENT REWARD RATING: Score: {score_str} | Efficiency: {eff}% ({succ} Success / {pen} Penalties)\n"

    def _get_findings_prompt_block(self, task_id: str = "global") -> str:
        findings = self.memory.get_all_findings(limit=15, task_id=task_id)
        if not findings:
            return ""
        items = [f"  - [{f['key']}]: {str(f['value'])[:200]}" for f in findings]
        return "\n═══════════════════════════════════════════════════════════\nSTORED RECON & VULNERABILITY FINDINGS (ACCUMULATED STATE)\n═══════════════════════════════════════════════════════════\n" + "\n".join(items) + "\n"

    def _build_prompt(self, task: str, task_type: str) -> str:
        tool_descriptions = "\n".join([f"  - {t.name}: {t.description}" for t in self.tools.values()])
        reflections_str = self._get_reflections_prompt_block()
        perf_str = self._get_performance_score_prompt_block()
        # Use task-scoped findings to avoid cross-scan data leakage
        task_id = getattr(self, '_current_task_id', 'global')
        findings_str = self._get_findings_prompt_block(task_id=task_id)

        prompt = f"""You are an Elite AI Security Research Agent with access to REAL executable tools and an integrated Auto-Tool Synthesis engine.

CURRENT TASK: "{task}"
TASK TYPE: {task_type}
{perf_str}
{findings_str}
═══════════════════════════════════════════════════════════
CORE RULES & SMART PARALLEL EXECUTION
═══════════════════════════════════════════════════════════
1. BATCHING FOR EFFICIENCY: To save API quota and speed up scanning, YOU CAN BATCH MULTIPLE INDEPENDENT TOOLS IN A SINGLE STEP!
   Set `action`: "batch" and list the tools in `result`.

2. MISSING TOOL AUTO-SYNTHESIS: If you need a Kali tool or specific capability not listed in the registry below (e.g., subfinder, dirsearch, custom exploit), request `action: "create_tool"` OR simply specify the requested tool name in `action`. The system will AUTOMATICALLY synthesize, compile, and live-load the tool for you on-the-fly!

3. **CRITICAL TOOL USAGE & CACHING RULES:**
   - CRITICAL: Basic recon data (DNS, WHOIS, SSL, IP geolocation, HTTP headers, robots/sitemap) is pre-collected at scan start. Use `discovery_cache` tool to retrieve cached data. DO NOT re-run basic recon tools (dns_lookup, whois_lookup, ssl_check, ipinfo_lookup, curl_headers) repeatedly!
   - NEVER pass a descriptive phrase as the `url` / `target` parameter. Always use the actual target URL/domain (e.g., `https://scholarhub.online`).
   - If you need to run `nvd_cve_lookup`, pass the keyword as a product name (e.g., "WordPress 7.0.4") NOT the URL.
   - If you need to call `write_file`, use the correct parameters: `path` (local file path) and `content` (string). Do NOT pass a dict.
   - If a tool fails due to missing binary, try to proceed with fallback tools (e.g., `fetch_url`, `curl_headers`) instead of repeating the same failed call.
   - Always check your arguments before calling a tool to avoid TypeErrors.

{reflections_str}
AVAILABLE TOOLS IN REGISTRY:
{tool_descriptions}

═══════════════════════════════════════════════════════════
JSON OUTPUT PROTOCOL (STRICT)
═══════════════════════════════════════════════════════════
You must respond with valid JSON containing exactly three keys:

For single tool execution:
{{
    "thought": "<Detailed step-by-step reasoning>",
    "action": "<tool_name>",
    "result": {{ "<param1>": "<val1>", "<param2>": "<val2>" }}
}}

For parallel batch execution (2-5 tools at once):
{{
    "thought": "<Detailed reasoning for running these tools in parallel>",
    "action": "batch",
    "result": [
        {{ "tool": "<tool1_name>", "args": {{ "<param>": "<val>" }} }},
        {{ "tool": "<tool2_name>", "args": {{ "<param>": "<val>" }} }}
    ]
}}

When completed:
{{
    "thought": "Assessment complete.",
    "action": "none",
    "result": "<Final comprehensive report of all findings>"
}}
"""
        return prompt

    def _auto_build_missing_tool(self, tool_name: str, tool_args: dict, task_id: str) -> bool:
        if self.__class__.__name__ == "GeneralToolBuilderAgent":
            return False
        try:
            self._safe_print(f"\n[⚡ AutoToolBuilder] Missing tool '{tool_name}' detected! Auto-synthesizing via ToolBuilderAgent...")
            self.memory.log_execution(task_id, self.__class__.__name__, "System",
                                      f"Auto-synthesizing missing tool: '{tool_name}' with args {tool_args}")

            from agents.tool_builder_agent import GeneralToolBuilderAgent
            from core.model_router import ModelRouter
            model_router = ModelRouter()
            provider = model_router.get_provider("GeneralToolBuilderAgent")
            builder = GeneralToolBuilderAgent(provider, self.memory, self.router, list(self.tools.values()))

            task_desc = (
                f"Build a production-ready Python tool class for '{tool_name}'.\n"
                f"Tool Name: {tool_name}\n"
                f"Expected Parameters: {tool_args}\n"
                f"Context/Objective: Synthesize missing capability '{tool_name}' to interact with target and perform requested security operations."
            )
            builder_res = builder.run(task_desc, max_steps=1, task_id=f"{task_id}-autobuild")

            from tools.registry import registry
            self.tools.update(registry.get_all_active_tools())
            return tool_name in self.tools
        except Exception as e:
            self._safe_print(f"[⚡ AutoToolBuilder] Auto-tool build failed: {e}")
            return False

    def _reflect_on_failure(self, action, error_output, task_type: str, task_id: str = "local-test"):
        try:
            action = str(action) if action is not None else "unknown"
            error_output = str(error_output) if error_output is not None else "unknown error"
            lesson = f"Action '{action}' failed with error: {error_output[:150]}. Avoid invalid parameters or incorrect syntax for this action."
            self.memory.save_reflection(self.__class__.__name__, task_type, action, error_output, lesson)
            self.memory.record_reward(self.__class__.__name__, task_id, -5, f"Execution error on '{action}'")
            self._safe_print(f"  [🧠 Self-Learning] Penalty (-5) & reflection recorded: {lesson[:100]}...")
        except Exception:
            pass

    def _extract_target_from_task(self, task: str) -> str:
        task_str = str(task)
        url_match = re.search(r'https?://[\w.:/-]+', task_str)
        if url_match:
            return url_match.group(0)
        key_patterns = [r'"target"\s*:\s*"([^"]+)"', r'"url"\s*:\s*"([^"]+)"', r'"domain"\s*:\s*"([^"]+)"', r'"host"\s*:\s*"([^"]+)"']
        for pattern in key_patterns:
            match = re.search(pattern, task_str, re.IGNORECASE)
            if match:
                domain = match.group(1)
                if domain and not domain.startswith(('http://', 'https://')):
                    return f"https://{domain}"
                return domain
        domain_match = re.search(r'([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}', task_str)
        if domain_match:
            return f"https://{domain_match.group(0)}"
        return "http://127.0.0.1"

    def _sanitize_args(self, tool_name: str, tool_args: dict) -> dict:
        """Ensure tool_args is a valid dict, sanitizes wrong values, and maps aliases."""
        if not isinstance(tool_args, dict):
            return {}
        clean = {k: v for k, v in tool_args.items() if v is not None}

        # Differentiate domain-only tools vs URL-based tools
        DOMAIN_ONLY_TOOLS = {
            "dns_lookup", "dns_a", "dns_mx", "dns_ns", "dns_txt", "dns_soa", "dns_recon",
            "crt_sh_search", "whois_lookup", "ipinfo_lookup", "subfinder_discovery",
            "theharvester", "theharvester_osint", "amass_subdomains", "sublist3r_subdomains",
            "findomain_discovery", "assetfinder_discovery", "dnsx_probe"
        }

        raw_target = str(clean.get("target") or clean.get("url") or clean.get("domain") or clean.get("host") or self._current_target)
        
        # Clean domain (strip http://, https://, slashes, ports)
        clean_domain = raw_target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip()
        # Clean URL (ensure http:// or https://)
        if not raw_target.startswith("http"):
            clean_url = "https://" + clean_domain
        else:
            clean_url = raw_target

        if tool_name in DOMAIN_ONLY_TOOLS:
            clean["domain"] = clean_domain
            clean["target"] = clean_domain
            clean["url"] = clean_domain
            clean["host"] = clean_domain
        else:
            clean["url"] = clean_url
            clean["target"] = clean_url
            clean["domain"] = clean_domain
            clean["host"] = clean_domain

        try:
            tool_instance = self.tools.get(tool_name)
            if tool_instance:
                sig = inspect.signature(tool_instance.execute)
                params = set(sig.parameters.keys())
                if 'targets' in params and 'targets' not in clean:
                    clean['targets'] = clean_domain if tool_name in DOMAIN_ONLY_TOOLS else clean_url
                if 'keyword' in params and 'keyword' not in clean:
                    clean['keyword'] = clean_domain
                if 'path' in params and 'path' not in clean and 'target' in clean:
                    clean['path'] = clean['target']
                if any(alias in params for alias in ['file_path', 'filepath', 'file']):
                    for alias in ['file_path', 'filepath', 'file']:
                        if alias in params and alias not in clean:
                            clean[alias] = clean.get('path') or clean['target']
                if 'domain' in params and 'domain' not in clean:
                    clean['domain'] = clean_domain
                if 'key' in params and 'key' not in clean:
                    clean['key'] = clean_domain
        except Exception:
            pass
        return clean

    def _get_cached_result(self, tool_name: str, tool_args: dict) -> str:
        """Check if tool output exists in discovery cache."""
        if self.__class__.__name__ == "InitialDiscoveryAgent":
            return None
        cache_path = "/tmp/discovery_cache.json"
        if not os.path.exists(cache_path):
            return None

        cache_key_map = {
            "dns_lookup": "dns",
            "dns_a": "dns",
            "whois_lookup": "whois",
            "ssl_check": "ssl",
            "ipinfo_lookup": "ip",
            "headers_only": "headers",
            "curl_headers": "headers",
            "fetch_url": "page"
        }

        cache_key = cache_key_map.get(tool_name)
        if not cache_key:
            return None

        try:
            with open(cache_path, "r") as f:
                data = json.load(f)
            if cache_key in data and data[cache_key]:
                val = data[cache_key]
                val_str = json.dumps(val, indent=2) if isinstance(val, (dict, list)) else str(val)
                return f"[🔄 Cache Hit] Returning cached result for '{tool_name}':\n{val_str[:1500]}"
        except Exception:
            pass
        return None

    def _execute_single_tool(self, tool_name: str, tool_args: dict, task_id: str) -> str:
        CACHEABLE_TOOLS = {"dns_lookup", "dns_a", "whois_lookup", "ssl_check", "ipinfo_lookup", "curl_headers", "headers_only", "fetch_url"}
        if tool_name in CACHEABLE_TOOLS:
            cached = self._get_cached_result(tool_name, tool_args)
            if cached:
                self._safe_print(f"  [🔄 Cache Hit] Using cached result for {tool_name}")
                self.memory.log_execution(task_id, self.__class__.__name__, "Observation", f"Cache hit for {tool_name}")
                return cached

        # Prevent repeated fetch_url on same URL (max 3 times)
        if tool_name == "fetch_url":
            url_key = str(tool_args.get("url") or tool_args.get("target") or tool_args.get("domain") or "")
            if url_key:
                self._fetch_count = getattr(self, "_fetch_count", {})
                self._fetch_count[url_key] = self._fetch_count.get(url_key, 0) + 1
                if self._fetch_count[url_key] >= 2:
                    self._reflect_on_failure(tool_name, "Repeated fetch_url on same URL; skipping.", self.__class__.__name__, task_id)
                    self._consecutive_failures += 1
                    return "SKIP: Repeated fetch_url, not executing again."

        # Normalize tool_name from dicts
        if isinstance(tool_name, dict):
            dict_item = tool_name
            tool_args = dict_item
            tool_name = dict_item.get("tool") or dict_item.get("name") or dict_item.get("action") or dict_item.get("tool_name")
            if not tool_name:
                matched = next((k for k in dict_item.keys() if k in self.tools), None)
                if matched:
                    tool_name = matched
                elif any(k in dict_item for k in ("command", "cmd", "script", "CommandLine")):
                    tool_name = "run_command"
                elif any(k in dict_item for k in ("url", "target_url", "uri")):
                    tool_name = "fetch_url"
                else:
                    tool_name = "unknown"
        tool_name = str(tool_name).strip()
        if '?' in tool_name:
            tool_name = tool_name.split('?')[0].strip()
        if tool_name not in self.tools:
            matched_tool = None
            for registered_name in self.tools.keys():
                if registered_name.lower() in tool_name.lower() or tool_name.lower().startswith(registered_name.lower()):
                    matched_tool = registered_name
                    break
            if matched_tool:
                tool_name = matched_tool
            else:
                built = self._auto_build_missing_tool(tool_name, tool_args, task_id)
                if not built or tool_name not in self.tools:
                    self._reflect_on_failure(tool_name, f"Tool '{tool_name}' not registered", self.__class__.__name__, task_id)
                    self._consecutive_failures += 1
                    if self._consecutive_failures >= 3:
                        return f"TOOL_FAILURE_TOO_MANY: Stopping due to repeated failures with '{tool_name}'"
                    return f"Error: Tool '{tool_name}' is not registered and auto-synthesis failed."

        tool = self.tools[tool_name]
        if isinstance(tool_args, dict):
            tool_args = self._sanitize_args(tool_name, tool_args)
        elif isinstance(tool_args, str):
            tool_args = {"target": tool_args, "url": tool_args, "domain": tool_args}
        else:
            tool_args = {"target": self._current_target, "url": self._current_target}

        try:
            self._emit("tool_start", tool=tool_name, args={k: str(v)[:200] for k, v in tool_args.items()}, task_id=task_id)
            output = tool.execute(**tool_args)
        except OSError as os_err:
            try:
                output = tool.execute(target=self._current_target, url=self._current_target, domain=self._current_target)
            except Exception as retry_err:
                return f"OSError in {tool_name}: {os_err} | Retry failed: {retry_err}"
        except TypeError as te:
            # Try to map target to targets (or keyword) if tool expects it
            try:
                if 'targets' in inspect.signature(tool.execute).parameters:
                    output = tool.execute(targets=tool_args.get('target') or tool_args.get('url') or self._current_target, **tool_args)
                else:
                    output = tool.execute(target=self._current_target, url=self._current_target, domain=self._current_target)
            except Exception as e2:
                err_msg = f"Error executing {tool_name}: {str(te)} | Fallback also failed: {e2}"
                self._reflect_on_failure(tool_name, err_msg, self.__class__.__name__, task_id)
                self._consecutive_failures += 1
                return err_msg
        except Exception as e:
            err_msg = f"Error executing {tool_name}: {str(e)}"
            self._reflect_on_failure(tool_name, err_msg, self.__class__.__name__, task_id)
            self._consecutive_failures += 1
            self._safe_print(f"  [🩺 ErrorHealingAgent] Auto-healing tool '{tool_name}' after exception...")
            if self._auto_build_missing_tool(tool_name, tool_args, task_id) and tool_name in self.tools:
                try:
                    output = str(self.tools[tool_name].execute(target=self._current_target, url=self._current_target) or "")
                except Exception:
                    output = err_msg
            else:
                return err_msg

        output = str(output) if output is not None else ""
        if output.startswith("Error") or "[ERROR]" in output or "Error:" in output or "Error executing" in output:
            self._reflect_on_failure(tool_name, output, self.__class__.__name__, task_id)
            self._consecutive_failures += 1
        else:
            self._consecutive_failures = 0
            self.memory.record_reward(self.__class__.__name__, task_id, +10, f"Successful execution of '{tool_name}'")
            self._emit("tool_output", tool=tool_name, output=output[:1000], task_id=task_id)
            flag_pattern = re.compile(r'(flag\{[^}]+\}|CTF\{[^}]+\}|picoCTF\{[^}]+\}|HTB\{[^}]+\}|THM\{[^}]+\})', re.IGNORECASE)
            flags = flag_pattern.findall(output)
            if flags:
                for f in flags:
                    print(f'  🚩 FLAG FOUND: {f}')
                    self.memory.log_execution(task_id, self.__class__.__name__, "Flag", f"🚩 FLAG CAPTURED: {f}")
        return output

    def _execute_batch_tools(self, batch_items: list, task_id: str) -> str:
        results = []
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for item in batch_items:
                if isinstance(item, dict):
                    tool_name = item.get("tool") or item.get("name") or item.get("action") or item.get("tool_name")
                    tool_args = item.get("args") or item.get("parameters") or item
                    if not tool_name:
                        matched = next((k for k in item.keys() if k in self.tools), None)
                        if matched:
                            tool_name = matched
                            tool_args = item[matched] if isinstance(item[matched], dict) else item
                        elif any(k in item for k in ("command", "cmd", "script", "CommandLine")):
                            tool_name = "run_command"
                        elif any(k in item for k in ("url", "target_url", "uri")):
                            tool_name = "fetch_url"
                else:
                    tool_name = str(item)
                    tool_args = {}
                if not tool_name or tool_name == "None":
                    continue
                futures.append((tool_name, executor.submit(self._execute_single_tool, tool_name, tool_args, task_id)))
            LONG_RUNNING_TOOLS = {
                "gobuster_scan", "nmap_scan", "wpscan_wordpress", "nuclei_scan",
                "feroxbuster_scan", "ffuf_fuzz", "dirsearch_scan", "wfuzz_fuzz",
                "zap_scan", "amass_subdomains", "theharvester_osint", "subfinder_discovery"
            }
            for tool_name, future in futures:
                tool_timeout = 240 if tool_name in LONG_RUNNING_TOOLS else 90
                try:
                    res = future.result(timeout=tool_timeout)
                    results.append(f"=== Batch Output: {tool_name} ===\n{res}")
                except FuturesTimeoutError:
                    results.append(f"=== Batch Output: {tool_name} ===\nError: Tool '{tool_name}' timed out after {tool_timeout} seconds")
                except Exception as e:
                    results.append(f"=== Batch Output: {tool_name} ===\nError: {e}")
        return "\n\n".join(results)

    def run(self, task: str, max_steps: int = 30, task_id: str = "local-test") -> str:
        agent_name = self.__class__.__name__
        self._safe_print(f"\n[*] [{agent_name}] Received Task: {str(task)[:150]}")
        self.memory.log_execution(task_id, agent_name, "System", f"Received Task: {str(task)[:300]}")

        task_type = agent_name
        context_history = []
        self._step_history = {}
        self._current_target = self._extract_target_from_task(task)
        self._current_task_id = task_id  # Store for use in _build_prompt() findings scope
        self._safe_print(f"[*] [{agent_name}] Extracted target: {self._current_target}")
        self._consecutive_failures = 0

        try:
            for step in range(1, max_steps + 1):
                if self.memory.is_task_cancelled(task_id):
                    cancel_msg = "Task cancelled by user."
                    self._safe_print(f"[{agent_name}] ⛔ {cancel_msg}")
                    self._emit("agent_done", result=cancel_msg, task_id=task_id)
                    return cancel_msg

                step_prefix = f"[{agent_name}] [Step {step}/{max_steps}]"
                self._safe_print(f"{step_prefix} Generating plan...")
                self.memory.log_execution(task_id, agent_name, "System", f"Step {step}/{max_steps}: Calling LLM...")

                base_prompt = self._build_prompt(task, task_type)
                if context_history:
                    context_str = "\n\n".join(context_history[-5:])
                    full_prompt = f"{base_prompt}\n\nPREVIOUS ACTIONS & TOOL OUTPUTS:\n{context_str}"
                else:
                    full_prompt = base_prompt

                response_dict = self.llm.generate(full_prompt)
                if not isinstance(response_dict, dict):
                    response_dict = {"thought": str(response_dict), "action": "none", "result": str(response_dict)}

                thought = response_dict.get("thought", "")
                action = response_dict.get("action", "none")
                result = response_dict.get("result", "")

                if thought:
                    self._safe_print(f"{step_prefix} Thought: {thought[:150]}...")
                    self.memory.log_execution(task_id, agent_name, "Thought", thought)
                    self._emit("agent_thought", thought=thought[:400], step=step, task_id=task_id)

                action_str = str(action).lower().strip()
                BATCH_ALIASES = {"run_multi", "multi_run", "batch_run", "run_batch", "execute_batch", "parallel", "multi", "run_multi()"}
                if action_str in BATCH_ALIASES:
                    action = "batch"
                    action_str = "batch"

                key = f"{action}:{str(result)[:50]}"
                self._step_history[key] = self._step_history.get(key, 0) + 1
                max_allowed = 2 if action in ["fetch_url", "curl_headers"] else 3
                if self._step_history[key] >= max_allowed:
                    self._safe_print(f"{step_prefix} REPETITIVE CALL DETECTED ({action})! Forcing completion.")
                    action = "none"
                    action_str = "none"
                    result = "Repetitive tool call capped to prevent loop."

                is_batch = (
                    action == "batch"
                    or isinstance(action, list)
                    or isinstance(action, dict)
                    or isinstance(result, list)
                    or (isinstance(result, dict) and ("commands" in result or any(isinstance(k, str) and k in self.tools and k not in self.PARAM_BLACKLIST for k in result.keys())))
                )
                if is_batch and action != "batch":
                    result = action if isinstance(action, (dict, list)) else result
                    action = "batch"

                if action_str in ["none", "null", "false", "done", "complete"]:
                    final_out = str(result) if result else thought
                    self._safe_print(f"{step_prefix} FINAL OUTPUT:\n{final_out[:200]}...")
                    self.memory.log_execution(task_id, agent_name, "Result", f"Completed: {final_out[:500]}")
                    self._emit("agent_done", result=final_out[:600], task_id=task_id)
                    return final_out

                if action_str in ["create_tool", "build_tool", "synthesize_tool"]:
                    tool_name = result.get("tool_name") if isinstance(result, dict) else str(result)
                    tool_args = result.get("args", {}) if isinstance(result, dict) else {}
                    built = self._auto_build_missing_tool(tool_name, tool_args, task_id)
                    output = f"✅ Tool '{tool_name}' created and registered!" if built else f"Error: Auto tool creation failed for '{tool_name}'."

                elif is_batch:
                    batch_items = []
                    if isinstance(result, list):
                        batch_items = result
                    elif isinstance(action, list):
                        batch_items = action
                    elif isinstance(result, dict):
                        list_key = next((k for k in ["tools", "commands", "operations", "tasks", "actions", "batch", "items"] if k in result and isinstance(result[k], list)), None)
                        if list_key:
                            batch_items = result[list_key]
                        else:
                            for t_name, t_args in result.items():
                                if t_name not in self.PARAM_BLACKLIST and t_name not in ["thought", "explanation", "analysis"]:
                                    batch_items.append({"tool": t_name, "args": t_args if isinstance(t_args, dict) else {"target": t_args}})
                    elif isinstance(action, dict):
                        list_key = next((k for k in ["tools", "commands", "operations", "tasks", "actions", "batch", "items"] if k in action and isinstance(action[k], list)), None)
                        if list_key:
                            batch_items = action[list_key]
                        else:
                            for t_name, t_args in action.items():
                                if t_name not in self.PARAM_BLACKLIST and t_name not in ["thought", "explanation", "analysis"]:
                                    batch_items.append({"tool": t_name, "args": t_args if isinstance(t_args, dict) else {"target": t_args}})

                    if batch_items:
                        self._safe_print(f"{step_prefix} Executing parallel batch of {len(batch_items)} tools...")
                        self.memory.log_execution(task_id, agent_name, "Action", f"Batch executing {len(batch_items)} tools")
                        output = self._execute_batch_tools(batch_items, task_id)
                    else:
                        # Batch parsing failed — log warning and try single tool fallback
                        warn_msg = f"Batch parse failed (action={str(action)[:100]}, result_type={type(result).__name__}). Falling back to fetch_url."
                        self._safe_print(f"{step_prefix} ⚠️  {warn_msg}")
                        self.memory.log_execution(task_id, agent_name, "System", warn_msg)
                        fallback_tool = "fetch_url"
                        with ThreadPoolExecutor(max_workers=1) as timeout_executor:
                            try:
                                future = timeout_executor.submit(self._execute_single_tool, fallback_tool, {"target": self._current_target}, task_id)
                                output = future.result(timeout=90)
                            except FuturesTimeoutError:
                                output = f"Error: Tool '{fallback_tool}' timed out after 90 seconds"
                else:
                    self._safe_print(f"{step_prefix} Executing: {action}({result})")
                    self.memory.log_execution(task_id, agent_name, "Action", f"{action}({result})")
                    tool_args = result if isinstance(result, dict) else {"target": result} if isinstance(result, str) else {}
                    LONG_RUNNING_TOOLS = {
                        "gobuster_scan", "nmap_scan", "wpscan_wordpress", "nuclei_scan",
                        "feroxbuster_scan", "ffuf_fuzz", "dirsearch_scan", "wfuzz_fuzz",
                        "zap_scan", "amass_subdomains", "theharvester_osint", "subfinder_discovery"
                    }
                    tool_timeout = 240 if action in LONG_RUNNING_TOOLS else 90
                    with ThreadPoolExecutor(max_workers=1) as timeout_executor:
                        try:
                            future = timeout_executor.submit(self._execute_single_tool, action, tool_args, task_id)
                            output = future.result(timeout=tool_timeout)
                        except FuturesTimeoutError:
                            output = f"Error: Tool '{action}' timed out after {tool_timeout} seconds"

                output_str = str(output) if output is not None else ""
                self._safe_print(f"{step_prefix} {action} output snippet: {output_str[:150]}...")
                self.memory.log_execution(task_id, agent_name, "Observation", output_str[:1000])
                context_history.append(f"Step {step}:\nAction: {action}\nResult Output:\n{output_str[:1500]}")

            fallback_msg = f"Task completed after reaching max limit of {max_steps} steps."
            self.memory.log_execution(task_id, agent_name, "Result", fallback_msg)
            return fallback_msg
        except Exception as e:
            error_msg = f"{agent_name} crashed with error: {str(e)}"
            self._safe_print(f"[{agent_name}] ⛔ {error_msg}")
            self.memory.log_execution(task_id, agent_name, "Error", error_msg)
            return error_msg
