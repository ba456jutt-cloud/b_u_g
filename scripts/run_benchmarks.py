import time
import os
import random
from tools.executor import ToolExecutor
from tools.registry import registry
from tools.file_tools import WriteFileTool, ReadFileTool

def run_benchmarks():
    print("=========================================")
    print("      Stress & Benchmark Testing         ")
    print("=========================================")
    
    # Setup
    registry.register(WriteFileTool, None) # Ignoring metadata for quick benchmark
    registry.register(ReadFileTool, None)
    
    test_file_path = os.path.join(os.getcwd(), "benchmark_test_file.txt")
    large_payload = "A" * (1024 * 1024) # 1 MB string
    
    results = {}

    # Benchmark: Large File Write
    start_time = time.time()
    ToolExecutor.execute("write_file", {"path": test_file_path, "content": large_payload})
    write_time = time.time() - start_time
    results["1MB_File_Write_Latency"] = f"{write_time:.4f} seconds"
    print(f"[*] 1MB Write: {write_time:.4f}s")

    # Benchmark: Large File Read
    start_time = time.time()
    ToolExecutor.execute("read_file", {"path": test_file_path})
    read_time = time.time() - start_time
    results["1MB_File_Read_Latency"] = f"{read_time:.4f} seconds"
    print(f"[*] 1MB Read:  {read_time:.4f}s")
    
    # Cleanup
    if os.path.exists(test_file_path):
        os.remove(test_file_path)

    # Save Results
    os.makedirs("docs", exist_ok=True)
    with open("docs/Benchmark_Results.md", "w") as f:
        f.write("# Performance Benchmarks\\n\\n")
        for k, v in results.items():
            f.write(f"- **{k}**: {v}\\n")
            
    print("[+] Benchmark results saved to docs/Benchmark_Results.md")

if __name__ == "__main__":
    run_benchmarks()
