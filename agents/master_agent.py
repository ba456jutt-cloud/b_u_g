import json
import logging
from agents.base_agent import BaseAgent
from core.model_router import ModelRouter

logger = logging.getLogger(__name__)

WORKFLOW_PIPELINES = {
    "full audit": [
        "InitialDiscoveryAgent", "ScopeManagementAgent", "PassiveReconAgent", "DNSIntelligenceAgent",
        "ReconAnalysisAgent", "AliveHostAgent", "PortScanAgent",
        "WebCrawlingAgent", "JSAnalysisAgent", "ParamDiscoveryAgent",
        "DirectoryEnumAgent", "VulnerabilityAnalysisAgent",
        "CVEResearchAgent", "AttackChainAgent", "PatchGeneratorAgent",
        "EvidenceAgent", "DeduplicationAgent", "ReportAgent",
        "NotificationAgent", "AuditLogAgent"
    ],
    "reconnaissance": [
        "InitialDiscoveryAgent", "ScopeManagementAgent", "PassiveReconAgent", "DNSIntelligenceAgent",
        "ReconAnalysisAgent", "AliveHostAgent", "PortScanAgent", "ReportAgent"
    ],
    "subdomain discovery": [
        "PassiveReconAgent", "DNSIntelligenceAgent", "AliveHostAgent", "ReportAgent"
    ],
    "web enumeration": [
        "WebCrawlingAgent", "JSAnalysisAgent", "ParamDiscoveryAgent",
        "DirectoryEnumAgent", "ReportAgent"
    ],
    "cve analysis": [
        "CVEResearchAgent", "AttackChainAgent", "PatchGeneratorAgent", "ReportAgent"
    ],
    "code review": [
        "CodeReviewAgent", "AttackChainAgent", "PatchGeneratorAgent", "ReportAgent"
    ],
    "auto patch": [
        "CodeReviewAgent", "PatchGeneratorAgent", "ReportAgent"
    ],
    "vulnerability": [
        "ReconAnalysisAgent", "VulnerabilityAnalysisAgent", "AttackChainAgent", "ReportAgent"
    ],
    "attack chain": [
        "AttackChainAgent", "EvidenceAgent", "ReportAgent"
    ],
    "poc": [
        "ScopeManagementAgent", "PoCVerificationAgent", "PatchGeneratorAgent",
        "EvidenceAgent", "ReportAgent"
    ],
    "poc verification": [
        "ScopeManagementAgent", "PoCVerificationAgent", "PatchGeneratorAgent",
        "EvidenceAgent", "ReportAgent"
    ],
    "ctf": [
        "CTFSolverAgent", "ReportAgent"
    ],
    "ctf solver": [
        "ScopeManagementAgent", "CTFSolverAgent", "ReportAgent"
    ],
    "web deep": [
        "WebCrawlingAgent", "ParamDiscoveryAgent", "DirectoryEnumAgent",
        "PoCVerificationAgent", "VulnerabilityAnalysisAgent", "ReportAgent"
    ],
    "deep scan": [
        "WebCrawlingAgent", "ParamDiscoveryAgent", "DirectoryEnumAgent",
        "PoCVerificationAgent", "VulnerabilityAnalysisAgent", "ReportAgent"
    ],
    "ctf web": [
        "ReconAnalysisAgent", "PortScanAgent", "WebCrawlingAgent",
        "ParamDiscoveryAgent", "VulnerabilityAnalysisAgent",
        "CTFSolverAgent", "AttackChainAgent", "ReportAgent"
    ],
    "quick scan": [
        "ReconAnalysisAgent", "PortScanAgent", "VulnerabilityAnalysisAgent", "ReportAgent"
    ],
    "payload": [
        "ScopeManagementAgent", "PoCVerificationAgent", "EvidenceAgent", "ReportAgent"
    ],
}

def detect_pipeline(task: str) -> list:
    task_lower = task.lower()
    ctf_keywords = ["ctf", "capture the flag", "challenge", "decode", "stego", "pwn", "reverse engineer"]
    if any(kw in task_lower for kw in ctf_keywords):
        return WORKFLOW_PIPELINES.get("ctf web", WORKFLOW_PIPELINES["full audit"])
    for keyword, pipeline in WORKFLOW_PIPELINES.items():
        if keyword in task_lower:
            return pipeline
    return WORKFLOW_PIPELINES["full audit"]


class MasterAgent(BaseAgent):
    def __init__(self, memory, router, tools, available_agents):
        model_router = ModelRouter()
        llm = model_router.get_provider("MasterAgent")
        super().__init__(llm_provider=llm, memory=memory, tools=tools, router=router)
        self.available_agents = available_agents

    def _build_planning_prompt(self, task: str) -> str:
        agent_descriptions = "\n".join([
            "- ReconAnalysisAgent: Active reconnaissance. Nmap port scans, web_security_audit, SSL checks, banner grabbing, Gobuster directory enum.",
            "- CVEResearchAgent: Threat intel. Uses nvd_cve_lookup to find real CVE IDs and CVSS scores for identified software versions.",
            "- CodeReviewAgent: SAST. Analyzes source code for injection flaws, auth bypass, and logic vulnerabilities.",
            "- VulnerabilityAnalysisAgent: Impact assessment. Scores findings by CVSS, maps attack vectors, and prioritizes by business risk.",
            "- ReportAgent: Executive reporting. Generates structured professional security reports from all gathered data.",
            "- GeneralToolBuilderAgent: Exploit & tool dev. Writes Python PoC exploits or custom security tools for identified vulnerabilities.",
            "- SecurityKnowledgeAgent: Defensive consulting. Provides OWASP mitigations and secure coding guidance.",
        ])
        available_names = ", ".join(self.available_agents.keys())
        return f"""You are the Elite Master Security Orchestrator.
Task: "{task}"

Your available specialized agents:
{agent_descriptions}

Currently initialized: {available_names}

Analyze the task and decide the FIRST agent to run. After that agent finishes, you will be called again with its output to decide the next step.

Respond with JSON:
- thought: Your analysis of the task, what phase this is, and why you're choosing this agent.
- action: The EXACT agent name to delegate to (e.g. 'ReconAnalysisAgent'), or 'none' if task is complete.
- result: Specific detailed instructions for the chosen agent. Include: exact target, what tools to use, what specific data to collect.
"""

    def _build_chaining_prompt(self, original_task: str, phase_num: int,
                                agent_name: str, agent_output: str, pipeline_remaining: list,
                                accumulated_results: dict = None) -> str:
        next_agents = ", ".join(pipeline_remaining) if pipeline_remaining else "none remaining"
        
        # Build summary of ALL completed phases so no findings are lost downstream
        history_summary = []
        if accumulated_results:
            for prev_agent, prev_out in accumulated_results.items():
                if prev_out and not str(prev_out).startswith("Error"):
                    history_summary.append(f"--- FINDINGS FROM [{prev_agent}] ---\n{str(prev_out)[:1500]}")
        
        accumulated_text = "\n\n".join(history_summary) if history_summary else str(agent_output)[:4000]

        return f"""You are the Elite Master Security Orchestrator. You are managing a multi-phase security pipeline.

ORIGINAL TASK: "{original_task}"
CURRENT PHASE: {phase_num}
JUST COMPLETED: {agent_name}

ACCUMULATED FINDINGS FROM ALL COMPLETED PHASES (MUST PASS ALL KEY DATA FORWARD):
{accumulated_text}

REMAINING PIPELINE AGENTS: {next_agents}

Your job: Decide the next agent to run, and craft PRECISE instructions.
CRITICAL STATE RULE: You MUST pass all key findings (open ports, versions, credentials, DB exposure, vulnerabilities, CVEs) from the accumulated findings above directly into the instructions for the next agent.
Do NOT let downstream agents (like DeduplicationAgent or ReportAgent) miss previously discovered findings.

Respond with JSON:
- thought: What key findings were gathered so far? What does the next agent need to do with them?
- action: Next agent name from the remaining pipeline, or 'none' if done.
- result: Precise instructions for the next agent containing all accumulated findings.
"""

    def run(self, task: str, task_id: str = "local-test", workflow: str = None, pre_recon_data: str = None) -> str:
        self._safe_print(f"[MasterAgent] Orchestrating Task: {task} (Workflow: {workflow})")
        self.memory.log_execution(task_id, self.__class__.__name__, "System", f"Orchestrating Task: {task}")

        if workflow and workflow.lower() in WORKFLOW_PIPELINES:
            pipeline = WORKFLOW_PIPELINES[workflow.lower()]
        else:
            pipeline = detect_pipeline(task)
        available_pipeline = [a for a in pipeline if a in self.available_agents]

        self.memory.log_execution(
            task_id, self.__class__.__name__, "System",
            f"Pipeline selected: {' → '.join(available_pipeline)}"
        )
        self._safe_print(f"[MasterAgent] Pipeline: {' → '.join(available_pipeline)}")

        self.memory.log_execution(task_id, self.__class__.__name__, "System", "Generating master plan via LLM...")
        plan_prompt = self._build_planning_prompt(task)
        plan_response = self.llm.generate(plan_prompt)

        thought = plan_response.get("thought", "")
        self.memory.log_execution(task_id, self.__class__.__name__, "Thought", thought)

        first_action = plan_response.get("action", "")
        first_instructions = plan_response.get("result", task)

        if first_action in self.available_agents and first_action in available_pipeline:
            idx = available_pipeline.index(first_action)
            pipeline_to_run = available_pipeline[idx:]
            current_instructions = first_instructions
        else:
            pipeline_to_run = available_pipeline
            current_instructions = task

        checkpoint = self.memory.get_checkpoint(task_id)
        completed_phases = []
        accumulated_results = {}
        if pre_recon_data:
            accumulated_results["PreReconEngine"] = pre_recon_data

        if checkpoint:
            completed_phases = checkpoint.get("completed_phases", [])
            accumulated_results = checkpoint.get("context_data", {})
            self._safe_print(f"[MasterAgent] 🔄 Resuming task '{task_id}' from checkpoint! Already completed: {completed_phases}")
            self.memory.log_execution(
                task_id, self.__class__.__name__, "System",
                f"Resuming task from checkpoint. Skipping completed phases: {completed_phases}"
            )

        final_output = None

        for phase_idx, agent_name in enumerate(pipeline_to_run):
            if self.memory.is_task_cancelled(task_id):
                cancel_msg = f"[MasterAgent] Task '{task_id}' was cancelled by user. Stopping pipeline."
                self._safe_print(cancel_msg)
                self.memory.log_execution(task_id, self.__class__.__name__, "System", cancel_msg)
                return "Task cancelled by user."

            if agent_name in completed_phases:
                self._safe_print(f"[MasterAgent] ⏩ Skipping completed phase ({agent_name}) from checkpoint.")
                continue

            phase_num = phase_idx + 1
            total_phases = len(pipeline_to_run)

            phase_log = f"Phase {phase_num}/{total_phases}: Delegating to {agent_name}"
            self._safe_print(f"[MasterAgent] {phase_log}")
            instructions_str = str(current_instructions) if current_instructions else ""
            self.memory.log_execution(task_id, self.__class__.__name__, "Action",
                                      f"{phase_log}\nInstructions: {instructions_str[:500]}")

            agent = self.available_agents[agent_name]
            try:
                agent_output = agent.run(instructions_str, task_id=task_id)
            except Exception as phase_error:
                agent_output = f"Agent {agent_name} encountered an error: {str(phase_error)[:500]}. Continuing to next phase."
                self.memory.log_execution(task_id, self.__class__.__name__, "Error",
                                          f"Phase {phase_num} ({agent_name}) crashed: {str(phase_error)[:300]}")
                self._safe_print(f"[MasterAgent] ⚠️ Phase {phase_num} ({agent_name}) crashed: {str(phase_error)[:200]}. Continuing...")

            if self.memory.is_task_cancelled(task_id) or "Task cancelled by user" in str(agent_output):
                cancel_msg = f"[MasterAgent] Task '{task_id}' was cancelled by user during {agent_name}. Stopping pipeline execution."
                self._safe_print(cancel_msg)
                self.memory.log_execution(task_id, self.__class__.__name__, "System", cancel_msg)
                return "Task cancelled by user."

            accumulated_results[agent_name] = agent_output
            completed_phases.append(agent_name)

            self.memory.save_checkpoint(task_id, task, completed_phases, agent_name, accumulated_results)

            result_log = f"Phase {phase_num} ({agent_name}) complete. Output length: {len(str(agent_output))} chars."
            self.memory.log_execution(task_id, self.__class__.__name__, "Result", result_log)
            self._safe_print(f"[MasterAgent] {result_log}")

            final_output = agent_output

            remaining_agents = pipeline_to_run[phase_idx + 1:]
            if remaining_agents:
                chain_prompt = self._build_chaining_prompt(
                    original_task=task,
                    phase_num=phase_num + 1,
                    agent_name=agent_name,
                    agent_output=str(agent_output),
                    pipeline_remaining=remaining_agents,
                    accumulated_results=accumulated_results
                )
                chain_response = self.llm.generate(chain_prompt)
                chain_thought = chain_response.get("thought", "")
                self.memory.log_execution(task_id, self.__class__.__name__, "Thought",
                                          f"[Chaining Phase {phase_num}→{phase_num+1}] {chain_thought}")

                next_action = chain_response.get("action", "")
                next_instructions = chain_response.get("result", "")

                if next_action in ("none", "null", "done", "complete") and not next_instructions:
                    self.memory.log_execution(task_id, self.__class__.__name__, "System",
                                              "LLM indicated pipeline complete. Stopping early.")
                    break

                if next_action in remaining_agents:
                    skip_idx = remaining_agents.index(next_action)
                    pipeline_to_run = pipeline_to_run[:phase_idx + 1] + remaining_agents[skip_idx:]
                    remaining_agents = pipeline_to_run[phase_idx + 2:]

                current_instructions = next_instructions or str(agent_output)[:1000]

        summary = self._build_final_summary(task, accumulated_results, task_id)
        return summary

    def _build_final_summary(self, original_task: str, results: dict, task_id: str) -> str:
        if not results:
            return "No results collected from pipeline."
        if "ReportAgent" in results and results["ReportAgent"]:
            final = results["ReportAgent"]
            self.memory.log_execution(task_id, self.__class__.__name__, "Result",
                                      f"Final Report from ReportAgent:\n{str(final)[:500]}...")
            return final
        parts = [f"# Security Analysis Report\nOriginal Task: {original_task}\n"]
        for agent_name, output in results.items():
            parts.append(f"\n## {agent_name} Findings\n{str(output)[:2000]}")
        consolidated = "\n".join(parts)
        self.memory.log_execution(task_id, self.__class__.__name__, "Result",
                                  f"Consolidated output from {len(results)} agents.")
        return consolidated
