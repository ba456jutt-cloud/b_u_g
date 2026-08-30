"""
InitialDiscoveryAgent - Runs basic recon tools ONCE at scan start, saves to /tmp/discovery_cache.json.
Prevents duplicate tool calls by downstream agents.
"""
import json
import os
from agents.base_agent import BaseAgent
from tools.pre_recon import PreReconEngine

class InitialDiscoveryAgent(BaseAgent):
    def run(self, task: str, max_steps: int = 5, task_id: str = "local-test") -> str:
        self._safe_print(f"\n[*] [InitialDiscoveryAgent] Running fast pre-recon discovery for: {task}")
        cache_path = "/tmp/discovery_cache.json"

        try:
            engine = PreReconEngine(task)
            recon_data = engine.run()

            cache_data = {
                "target": task,
                "dns": recon_data.get("dns_records", {}),
                "whois": recon_data.get("whois", {}),
                "ssl": recon_data.get("ssl_info", {}),
                "ip": recon_data.get("ip_geo", {}),
                "headers": recon_data.get("http_headers", {}),
                "robots_and_sitemap": recon_data.get("robots_and_sitemap", {})
            }

            with open(cache_path, "w") as f:
                json.dump(cache_data, f, indent=2)

            summary = engine.get_summary_text()
            self._safe_print(f"  [✅ InitialDiscovery] Pre-recon complete! Cache saved to {cache_path}")
            self.memory.log_execution(task_id, self.__class__.__name__, "Result", f"Cache saved to {cache_path}\n{summary}")
            return f"Initial discovery complete. Cache saved to {cache_path}\n\n{summary}"

        except Exception as e:
            err_msg = f"Initial discovery error: {e}"
            self._safe_print(f"  [⚠️ InitialDiscovery] Error: {e}")
            return err_msg

    def _build_prompt(self, task: str, task_type: str) -> str:
        tool_descriptions = "\n".join([f"  - {t.name}: {t.description}" for t in self.tools.values()])
        return f"""You are the InitialDiscoveryAgent. Your job is to run ONLY basic tools ONCE and save results to /tmp/discovery_cache.json.

TARGET: "{task}"
AVAILABLE TOOLS:
{tool_descriptions}
"""
