import os
from config.settings import settings
from agents import ReconAnalysisAgent, CVEResearchAgent, CodeReviewAgent, SecurityKnowledgeAgent, VulnerabilityAnalysisAgent, ReportAgent, MasterAgent
from memory.long_term_mem import LongTermMemoryDB
from router.task_router import TaskRouter
from core.model_router import ModelRouter
from tools.registry import registry
from tools.system import ReadFileTool, WriteFileTool, RunCommandTool

def main():
    print("=========================================")
    print("   Testing Phase 3: Master Orchestrator  ")
    print("=========================================\n")

    # Ensure memory is initialized
    memory = LongTermMemoryDB()
    router = TaskRouter()
    model_router = ModelRouter()

    # Register basic tools
    registry.register(ReadFileTool)
    registry.register(WriteFileTool)
    registry.register(RunCommandTool)
    tools = list(registry.get_all_active_tools().values())

    print("[*] Initializing specialized agents with routed models...")
    agents_dict = {
        "ReconAnalysisAgent": ReconAnalysisAgent(llm_provider=model_router.get_provider("ReconAnalysisAgent"), memory=memory, router=router, tools=tools),
        "CVEResearchAgent": CVEResearchAgent(llm_provider=model_router.get_provider("CVEResearchAgent"), memory=memory, router=router, tools=tools),
        "CodeReviewAgent": CodeReviewAgent(llm_provider=model_router.get_provider("CodeReviewAgent"), memory=memory, router=router, tools=tools),
        "SecurityKnowledgeAgent": SecurityKnowledgeAgent(llm_provider=model_router.get_provider("SecurityKnowledgeAgent"), memory=memory, router=router, tools=tools),
        "VulnerabilityAnalysisAgent": VulnerabilityAnalysisAgent(llm_provider=model_router.get_provider("VulnerabilityAnalysisAgent"), memory=memory, router=router, tools=tools),
        "ReportAgent": ReportAgent(llm_provider=model_router.get_provider("ReportAgent"), memory=memory, router=router, tools=tools)
    }

    # Initialize MasterAgent
    master = MasterAgent(memory=memory, router=router, tools=tools, available_agents=agents_dict)

    # Test Task
    task = "Provide a brief explanation of CVE-2021-44228 (Log4Shell) and recommend a mitigation."
    print(f"\n>>> Sending Task to MasterAgent:\n'{task}'\n")
    
    result = master.run(task)
    
    print("\n=========================================")
    print("            FINAL OUTPUT                 ")
    print("=========================================")
    print(result)

if __name__ == "__main__":
    main()
