#!/usr/bin/env python3
"""
Autonomous AI Bug Bounty & Vulnerability Research Agentic System — CLI Interface
Local-first, modular command line utility for authorized security testing.
"""
import sys
import os
import argparse
import json
import uuid

# Add root directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from memory.sqlite_mem import MemoryDB
from router.task_router import TaskRouter
from core.model_router import ModelRouter
from tools.registry import registry
from agents.master_agent import MasterAgent
from agents import (
    ReconAnalysisAgent, CVEResearchAgent, CodeReviewAgent,
    SecurityKnowledgeAgent, VulnerabilityAnalysisAgent,
    ReportAgent, GeneralToolBuilderAgent, AttackChainAgent,
    ScopeManagementAgent, PassiveReconAgent, DNSIntelligenceAgent,
    AliveHostAgent, PortScanAgent, WebCrawlingAgent, JSAnalysisAgent,
    ParamDiscoveryAgent, DirectoryEnumAgent, EvidenceAgent,
    DeduplicationAgent, NotificationAgent, AuditLogAgent
)

def print_banner():
    banner = """
 ╔═════════════════════════════════════════════════════════════════════════╗
 ║ 🛡️  AUTONOMOUS AI BUG BOUNTY & VULNERABILITY RESEARCH SYSTEM           ║
 ║     Multi-Agent Orchestration • 30+ Kali Tools • Local-First Execution  ║
 ╚═════════════════════════════════════════════════════════════════════════╝
"""
    print(banner)

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Autonomous AI Bug Bounty & Vulnerability Research CLI")
    parser.add_argument("target", help="Target domain, URL, or scope file (e.g. example.com)")
    parser.add_argument("--workflow", choices=["full audit", "reconnaissance", "subdomain discovery", "web enumeration", "cve analysis", "code review", "vulnerability"], default="full audit", help="Workflow pipeline to execute")
    parser.add_argument("--out-of-scope", help="Comma-separated out-of-scope targets to exclude", default="")
    parser.add_argument("--report-pdf", action="store_true", help="Generate export report in PDF format")
    args = parser.parse_args()

    target = args.target.strip()
    workflow = args.workflow
    task_id = str(uuid.uuid4())[:8]

    # Validate Scope
    scope_agent = ScopeManagementAgent(llm_provider=None, memory=None, router=None, tools=[])
    oos_list = [x.strip() for x in args.out_of_scope.split(",") if x.strip()]
    scope_check = scope_agent.validate_scope(target, allowed_rules=[target], out_of_scope_rules=oos_list)

    if not scope_check.get("allowed", False):
        print(f"❌ SCOPE ERROR: {scope_check.get('reason')}")
        sys.exit(1)

    print(f"✅ Scope Validated: Target '{target}' is AUTHORIZED.")
    print(f"🚀 Starting Workflow: [{workflow.upper()}] (Task ID: {task_id})\n")

    memory = MemoryDB()
    router = TaskRouter()
    model_router = ModelRouter()
    tools = list(registry.get_all_active_tools().values())

    agent_classes = [
        ReconAnalysisAgent, CVEResearchAgent, CodeReviewAgent,
        SecurityKnowledgeAgent, VulnerabilityAnalysisAgent,
        ReportAgent, GeneralToolBuilderAgent, AttackChainAgent,
        ScopeManagementAgent, PassiveReconAgent, DNSIntelligenceAgent,
        AliveHostAgent, PortScanAgent, WebCrawlingAgent, JSAnalysisAgent,
        ParamDiscoveryAgent, DirectoryEnumAgent, EvidenceAgent,
        DeduplicationAgent, NotificationAgent, AuditLogAgent
    ]

    agents_dict = {
        cls.__name__: cls(
            llm_provider=model_router.get_provider(cls.__name__),
            memory=memory, router=router, tools=tools
        )
        for cls in agent_classes
    }

    master = MasterAgent(memory=memory, router=router, tools=tools, available_agents=agents_dict)
    
    task_prompt = f"Perform {workflow} on target: {target}"
    result = master.run(task_prompt, task_id=task_id)

    print("\n" + "═"*70)
    print(f"🎉 WORKFLOW COMPLETE — TASK ID: {task_id}")
    print("═"*70)
    print(result[:1500])

    if args.report_pdf:
        from tools.pdf_generator import generate_pdf_report
        # Fetch execution logs from DB
        conn = memory._init_db() if hasattr(memory, '_init_db') else None
        report_path = generate_pdf_report(task_id, logs=[{"agent_name": "MasterAgent", "log_type": "Result", "content": result}])
        print(f"\n📄 Generated Report PDF: {report_path}")

if __name__ == "__main__":
    main()
