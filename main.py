from core.llm_provider import GeminiProvider
from memory.sqlite_mem import MemoryDB
from router.task_router import TaskRouter
from agents.base_agent import BaseAgent
from tools.system import ReadFileTool, WriteFileTool, RunCommandTool

def main():
    print("=========================================")
    print("   AI Cyber Security Agent - Phase 1     ")
    print("=========================================\n")

    # Initialize Core Components
    print("[*] Initializing components...")
    
    llm = GeminiProvider()
    memory = MemoryDB()
    router = TaskRouter()
    
    # Initialize Tools
    tools = [
        ReadFileTool,
        WriteFileTool,
        RunCommandTool
    ]
    
    # Initialize Agent
    agent = BaseAgent(llm_provider=llm, memory=memory, router=router, tools=tools)
    print("[+] Initialization complete.\n")
    
    # Demo Task 1: System Command
    task1 = "Please run 'whoami' to see the current user."
    print(f"\n>>> Starting Task 1: {task1}")
    agent.run(task1)
    
    # Demo Task 2: Write File
    task2 = "Write a file named 'hello.txt' with the content 'Hello from Agent!'"
    print(f"\n>>> Starting Task 2: {task2}")
    agent.run(task2)
    
    print("\n[+] Demo execution completed successfully.")
    
if __name__ == "__main__":
    main()
