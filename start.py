import subprocess
import sys
import time

import os
os.environ["PATH"] = os.environ.get("PATH", "") + ":/home/ahmad/go/bin:/usr/local/bin"

def start_services():
    base_dir = "/home/ahmad/Documents/Agent"
    
    # Commands for all three services
    export_path = "export PATH=$PATH:/home/ahmad/go/bin:/usr/local/bin && "
    api_cmd = f"{export_path}cd {base_dir} && source venv/bin/activate && uvicorn api.main:app --reload"
    huey_cmd = f"{export_path}cd {base_dir} && source venv/bin/activate && huey_consumer core.queue.huey_queue -w 4 -k thread"
    frontend_cmd = f'{export_path}export NVM_DIR="$HOME/.config/nvm" && [ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh" && nvm use 20 && cd {base_dir}/frontend && npm run dev'

    print("=========================================")
    print("  Starting Bug Bounty Copilot Workspace  ")
    print("=========================================")
    print("[+] Starting FastAPI Backend (Port 8000)")
    print("[+] Starting Huey Task Queue Worker")
    print("[+] Starting Next.js Frontend (Port 3000)")
    print("=========================================")
    print("Press Ctrl+C to stop all services.\n")

    # Start all processes
    p1 = subprocess.Popen(f"bash -c '{api_cmd}'", shell=True)
    p2 = subprocess.Popen(f"bash -c '{huey_cmd}'", shell=True)
    p3 = subprocess.Popen(f"bash -c '{frontend_cmd}'", shell=True)

    try:
        # Keep the main script running to catch Ctrl+C
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Shutting down all services gracefully...")
        p1.terminate()
        p2.terminate()
        p3.terminate()
        print("Done.")
        sys.exit(0)

if __name__ == '__main__':
    start_services()
