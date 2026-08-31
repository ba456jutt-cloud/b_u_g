"""
MLScanAgent — Agent wrapper for MLScanEngine
=============================================
This agent runs the ML Scan Engine as Stage 0.
It does NOT call external scanning tools directly or waste LLM steps.
It executes ML-driven reconnaissance and outputs structured scan JSON.
"""
import json
import logging
from agents.base_agent import BaseAgent
from ml_engine.scan_intelligence import MLScanEngine

logger = logging.getLogger(__name__)


class MLScanAgent(BaseAgent):
    """
    Intelligent ML Reconnaissance Agent.
    Executes MLScanEngine to probe target, bypass firewalls, classify services,
    and score vulnerabilities.
    """

    def __init__(self, llm_provider=None, memory=None, router=None, tools=None):
        if llm_provider is not None:
            super().__init__(llm_provider, memory, router, tools or [])
        else:
            self.memory = memory
        self.engine = MLScanEngine()

    def run(self, task: str, max_steps: int = 1, task_id: str = "local-test") -> str:
        agent_name = self.__class__.__name__
        self._safe_print(f"\n[*] [{agent_name}] Received Task: {str(task)[:150]}")
        if self.memory:
            self.memory.log_execution(task_id, agent_name, "System", f"Starting ML Scan for task: {str(task)[:150]}")

        target = self._extract_target_from_task(task)
        self._safe_print(f"[*] [{agent_name}] Extracted target: {target}")

        # Execute ML Scan Engine directly (0 LLM steps needed!)
        results = self.engine.scan(target, task_id=task_id)

        # Convert result to clean formatted JSON string
        result_json = json.dumps(results, indent=2)

        if self.memory:
            self.memory.save_finding(f"ml_scan_{task_id}", result_json, task_id=task_id)
            self.memory.log_execution(task_id, agent_name, "Output", f"ML Scan complete for {target}. Found {len(results.get('open_ports', []))} open ports.")

        return result_json
