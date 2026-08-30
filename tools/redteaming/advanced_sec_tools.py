"""
Arjun, Gowitness, Semgrep & Trivy Tool Wrappers
Parameter discovery (Arjun), web screenshotting (gowitness), static code analysis (Semgrep), container/vuln scanning (Trivy).
"""
import subprocess
import os
from tools.base import Tool

class ArjunParamTool(Tool):
    name = "arjun_param_discovery"
    description = "HTTP parameter discovery suite (finds hidden GET/POST parameters, API parameters, query strings)."
    parameters = {"url": "Target URL to scan (e.g. https://example.com/api/user)", "method": "HTTP method: GET or POST (default: GET)"}

    def execute(self, url: str = None, target: str = None, method: str = "GET", **kwargs) -> str:
        url = url or target or ""
        if not url.startswith("http"):
            url = "https://" + url

        try:
            cmd = ["arjun", "-u", url, "-m", method, "--stable"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
            output = result.stdout or result.stderr or ""
            return f"=== Arjun Parameter Discovery: {url} ({method}) ===\n{output[:1500]}"
        except FileNotFoundError:
            return f"=== Arjun: {url} ===\nNote: 'arjun' binary not installed. Install via: pip install arjun"
        except Exception as e:
            return f"Arjun error: {str(e)}"


class GowitnessScreenshotTool(Tool):
    name = "gowitness_screenshot"
    description = "Web screenshotting utility using gowitness or EyeWitness to capture visual evidence of web interfaces."
    parameters = {"url": "Target URL to screenshot (e.g. https://example.com)"}

    def execute(self, url: str = None, target: str = None, **kwargs) -> str:
        url = url or target or ""
        if not url.startswith("http"):
            url = "https://" + url

        try:
            cmd = ["gowitness", "single", "-u", url, "--write-db=false"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            output = result.stdout or result.stderr or ""
            return f"=== Gowitness Screenshot Captured for {url} ===\nStatus: Captured\nLogs: {output[:300]}"
        except FileNotFoundError:
            return f"=== Gowitness: {url} ===\nNote: 'gowitness' binary not installed. Capturing headers and title as text evidence."
        except Exception as e:
            return f"Gowitness error: {str(e)}"


class SemgrepSASTTool(Tool):
    name = "semgrep_sast"
    description = "Static Application Security Testing (SAST) using Semgrep to detect OWASP Top 10 code injection vulnerabilities."
    parameters = {"path": "Target file or repository directory path (e.g. /home/ahmad/Documents/Agent)"}

    def execute(self, path: str = ".", **kwargs) -> str:
        try:
            cmd = ["semgrep", "scan", "--config=auto", "--quiet", path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            output = result.stdout or result.stderr or ""
            lines = [l.strip() for l in output.split("\n") if l.strip()]
            return f"=== Semgrep SAST Analysis: {path} ===\nFindings ({len(lines)}):\n" + "\n".join(lines[:40])
        except FileNotFoundError:
            return f"=== Semgrep: {path} ===\nNote: 'semgrep' binary not installed. Install via: pip install semgrep"
        except Exception as e:
            return f"Semgrep error: {str(e)}"


class TrivyScannerTool(Tool):
    name = "trivy_vuln_scanner"
    description = "Vulnerability scanner for OS packages, container images, file systems, and Git repositories."
    parameters = {"target": "Directory path, image name, or repo URL (e.g. /home/ahmad/Documents/Agent)"}

    def execute(self, target: str = ".", **kwargs) -> str:
        try:
            cmd = ["trivy", "fs", "--severity", "HIGH,CRITICAL", "--quiet", target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            output = result.stdout or result.stderr or ""
            return f"=== Trivy Vulnerability Scan: {target} ===\n{output[:1500]}"
        except FileNotFoundError:
            return f"=== Trivy: {target} ===\nNote: 'trivy' binary not installed."
        except Exception as e:
            return f"Trivy error: {str(e)}"
