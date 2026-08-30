import subprocess
from tools.base import Tool

class NmapScanTool(Tool):
    name = "nmap_scan"
    description = (
        "Runs an Nmap port scan against a target IP or hostname. "
        "Flags example: '-T4 --top-ports 100 -sV --open' or '-sV -p 80,443'."
    )
    parameters = {
        "target": "Target IP or domain (e.g. 45.33.32.156 or scanme.nmap.org)",
        "flags": "Nmap flags (default: '-T4 --top-ports 100 -sV --open')"
    }

    def execute(self, target: str = None, host: str = None, url: str = None, flags: str = "-T4 --top-ports 100 -sV --open", **kwargs) -> str:
        import shutil
        if not shutil.which("nmap"):
            return "Error: CLI Tool 'nmap' is not installed on system PATH."

        target = target or host or url or kwargs.get("target_url") or kwargs.get("ip") or "127.0.0.1"
        target = str(target).replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip()
        if not target or target == "localhost":
            target = "127.0.0.1"


        # Clean flags to ensure valid nmap syntax
        parts = flags.split()
        safe_flags = []
        i = 0
        while i < len(parts):
            f = parts[i]
            # Fix invalid port syntax like -p T:1-1000,U:1-1000
            if f.startswith("-p") and ("T:" in f or "U:" in f):
                safe_flags.extend(["-p", "1-1000"])
            elif f == "--top-ports" and i + 1 < len(parts) and parts[i+1].isdigit():
                safe_flags.extend([f, parts[i+1]])
                i += 1
            else:
                safe_flags.append(f)
            i += 1

        if "-Pn" not in safe_flags:
            safe_flags.insert(0, "-Pn")

        cmd = ["nmap"] + safe_flags + [target]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            output = result.stdout or result.stderr or ""
            return output
        except subprocess.TimeoutExpired:
            return f"Error: Nmap scan timed out after 5 minutes for {target}."
        except Exception as e:
            return f"Error executing Nmap: {str(e)}"
