import os
import uuid
from huey import SqliteHuey
from config.settings import settings

db_path = os.path.join(os.path.dirname(settings.MEMORY_DB_PATH), "queue.db")
huey_queue = SqliteHuey('agent_tasks', filename=db_path)

@huey_queue.task()
def process_task_async(task_name: str, workflow: str = None, task_id: str = None):
    """Background job — full agent pipeline via MasterAgent orchestrator."""
    if not task_id:
        task_id = str(uuid.uuid4())

    import logging
    logger = logging.getLogger(__name__)
    logger.info(f"Starting task: {task_name} [{task_id}]")

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
        DeduplicationAgent, NotificationAgent, AuditLogAgent, PatchGeneratorAgent,
        CTFSolverAgent
    )

    memory = MemoryDB()
    if memory.is_task_cancelled(task_id):
        logger.info(f"Task {task_id} was cancelled before starting. Skipping.")
        memory.log_execution(task_id, "System", "Status", "Task cancelled by user before start.")
        return "Task cancelled"

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
        DeduplicationAgent, NotificationAgent, AuditLogAgent, PatchGeneratorAgent,
        CTFSolverAgent
    ]


    agents_dict = {
        cls.__name__: cls(
            model_router.get_provider(cls.__name__),
            memory, router, tools
        )
        for cls in agent_classes
    }

    master = MasterAgent(memory=memory, router=router, tools=tools, available_agents=agents_dict)
    memory.log_execution(task_id, "System", "Status", f"Task started: {task_name}")

    # Run Automated Pre-Recon Engine
    try:
        from tools.pre_recon import PreReconEngine
        memory.log_execution(task_id, "PreReconEngine", "Action", f"Running Automated Pre-Recon Engine for {task_name}...")
        engine = PreReconEngine(task_name)
        pre_recon_summary = engine.get_summary_text()
        memory.log_execution(task_id, "PreReconEngine", "Observation", pre_recon_summary)
    except Exception as pre_err:
        pre_recon_summary = f"PreReconEngine Note: {pre_err}"

    try:
        result = master.run(task_name, task_id=task_id, workflow=workflow, pre_recon_data=pre_recon_summary)
        logger.info(f"Task complete: {task_name}")
        memory.log_execution(task_id, "System", "Status", f"Task complete. Result length: {len(str(result))}")
        return result
    except Exception as e:
        logger.error(f"Task failed: {e}")
        memory.log_execution(task_id, "System", "Error", f"Task failed: {str(e)}")
        raise e
