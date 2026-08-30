import os
import subprocess
import ssl
import urllib.request
import re
from tools.base import Tool

class ReadFileTool(Tool):
    name = "read_file"
    description = "Reads content from a specified file path."
    parameters = {"path": "Local file path to read"}

    def execute(self, path: str = None, file_path: str = None, filepath: str = None, file: str = None, **kwargs) -> str:
        # Accept multiple aliases
        target_path = path or file_path or filepath or file or ""
        # Ignore URLs
        if target_path.startswith("http"):
            return "Error: Please provide a local file path, not a URL."
        if not target_path:
            return "Error: Provide a valid file path to read."
        try:
            with open(target_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            return f"Error reading file {target_path}: {str(e)}"


class WriteFileTool(Tool):
    name = "write_file"
    description = "Writes content to a specified local file path."
    parameters = {"path": "Local file path (e.g. /tmp/report.md)", "content": "Text content to write"}

    def execute(self, path: str = None, content: str = None, file_path: str = None, filepath: str = None, text: str = "", **kwargs) -> str:
        target_path = path or file_path or filepath or ""
        if not target_path:
            return "Error: Provide a valid file path."
        if target_path.startswith("http"):
            target_path = "/tmp/report_output.md"  # fallback
        write_content = content or text or ""
        try:
            dir_name = os.path.dirname(target_path)
            if dir_name:
                os.makedirs(dir_name, exist_ok=True)
            with open(target_path, 'w', encoding='utf-8') as f:
                f.write(write_content)
            return f"Successfully wrote to {target_path}"
        except Exception as e:
            return f"Error writing file: {str(e)}"

class RunCommandTool(Tool):
    name = "run_command"
    description = "Executes a shell command safely."
    parameters = {"command": "The bash command to execute."}

    def execute(self, command: str = None, cmd: str = None, script: str = None, CommandLine: str = None, args: str = None, **kwargs) -> str:
        raw_cmd = command or cmd or script or CommandLine or args
        if not raw_cmd:
            for key, val in kwargs.items():
                if isinstance(val, str) and len(val) > 2 and key not in ('target', 'url', 'domain', 'host'):
                    raw_cmd = val
                    break
        if not raw_cmd:
            return "Error: No command provided. Pass command as 'command', 'cmd', or 'script' parameter."

        raw_cmd = re.sub(r'^(Command:|Execute:|Run:|Shell:|Bash:|\$)\s*', '', str(raw_cmd).strip(), flags=re.IGNORECASE)
        raw_cmd = raw_cmd.strip('`').strip()

        if not raw_cmd or raw_cmd == "None":
            return "Error: Empty command string after cleanup."

        blocklist = ["rm -rf /", "mkfs", "dd if=", "fdisk", "shutdown", "reboot"]
        for blocked in blocklist:
            if blocked in raw_cmd:
                return f"Execution blocked: Command contains unsafe pattern '{blocked}'."

        try:
            result = subprocess.run(raw_cmd, shell=True, capture_output=True, text=True, timeout=120)
            stdout = result.stdout.strip() if result.stdout else ""
            stderr = result.stderr.strip() if result.stderr else ""
            output = stdout
            if stderr:
                output += f"\n[STDERR]: {stderr}" if stdout else stderr
            if not output:
                output = f"Command completed with exit code {result.returncode}"
            return output[:5000]
        except subprocess.TimeoutExpired:
            return f"Error: Command '{raw_cmd[:50]}' timed out after 120s."
        except Exception as e:
            return f"Exception executing command: {str(e)}"


class FetchURLTool(Tool):
    name = "fetch_url"
    description = "Fetches content and response headers from a target URL."
    parameters = {"url": "Target URL to inspect"}

    def execute(self, url: str = None, target: str = None, **kwargs) -> str:
        target_url = url or target or kwargs.get("domain") or kwargs.get("host") or kwargs.get("target_url") or ""
        target_url = str(target_url).strip()

        match = re.search(r'(https?://[^\s\'"\}]+|[a-zA-Z0-9.\-]+:[0-9]+|[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})', target_url)
        if match:
            target_url = match.group(1).rstrip('/,;}')

        if not target_url or "provide a valid url" in target_url.lower():
            return "Error: Provide a valid URL to fetch."

        if not target_url.startswith(("http://", "https://")):
            target_url = "http://" + target_url

        import requests
        try:
            resp = requests.get(target_url, timeout=15, verify=False, allow_redirects=True,
                               headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityAuditBot/1.0'})
            headers_str = '\n'.join(f'{k}: {v}' for k, v in resp.headers.items())
            body_snippet = resp.text[:2000]
            return f"HTTP {resp.status_code}\nURL: {resp.url}\nHEADERS:\n{headers_str}\n\nBODY (snippet):\n{body_snippet}"
        except Exception as e:
            # Secondary fallback using curl command if requests fails
            try:
                import subprocess
                cmd = f"curl -sSL -k -I --connect-timeout 10 '{target_url}'"
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
                if res.stdout and len(res.stdout) > 10:
                    return f"HTTP HEADERS (via curl):\n{res.stdout[:2000]}"
            except Exception:
                pass
            return f"Failed to fetch {target_url}: {str(e)}"
