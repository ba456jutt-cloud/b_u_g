import requests
import os
os.environ["PATH"] = os.environ.get("PATH", "") + ":/home/ahmad/go/bin:/usr/local/bin"
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class Tool(ABC):
    name: str = ""
    description: str = ""
    parameters: dict = {}

    @abstractmethod
    def execute(self, **kwargs) -> str:
        pass


class StandardSecurityTool(Tool, ABC):
    """
    Standard Base Template for All Security Verification Tools.
    Provides robust URL normalization, default timeouts, error handling, and structured diagnostic outputs.
    """

    def normalize_url(self, target: str) -> str:
        import re
        if not target:
            return ""
        target_str = str(target).strip()

        # Extract URL pattern if embedded inside dict/prose text
        match = re.search(r'(https?://[^\s\'"\}]+|[a-zA-Z0-9.\-]+:[0-9]+|[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})', target_str)
        if match:
            extracted = match.group(1).rstrip('/,;}')
            if not extracted.startswith(("http://", "https://")):
                return f"http://{extracted}"
            return extracted

        if not target_str.startswith(("http://", "https://")):
            return f"http://{target_str}"
        return target_str


    def safe_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Any] = None,
        timeout: int = 10,
        verify_ssl: bool = False
    ) -> tuple[Optional[requests.Response], Optional[str]]:
        """
        Executes HTTP requests safely with built-in timeouts and exception catching.
        Returns (response_object, error_message).
        """
        if headers is None:
            headers = {"User-Agent": "Security-Audit-Agent/1.0"}

        try:
            resp = requests.request(
                method=method,
                url=self.normalize_url(url),
                headers=headers,
                data=data,
                timeout=timeout,
                verify=verify_ssl
            )
            return resp, None
        except requests.exceptions.Timeout:
            return None, f"Connection timed out after {timeout} seconds."
        except requests.exceptions.SSLError:
            return None, "SSL/TLS verification failed."
        except requests.exceptions.RequestException as e:
            return None, f"Network execution error: {str(e)}"

    def format_diagnostic_report(
        self,
        target: str,
        status: str,
        details: str,
        findings: Optional[dict] = None
    ) -> str:
        """Helper to format structured audit reports."""
        output = [
            f"=== Audit Report: {self.name} ===",
            f"Target : {target}",
            f"Status : {status}",
            f"Details: {details}"
        ]
        if findings:
            output.append("Findings:")
            for k, v in findings.items():
                output.append(f"  - {k}: {v}")
        return "\n".join(output)

    def check_binary(self, binary_name: str) -> tuple[bool, str]:
        """Check if CLI binary exists on host system; returns (exists, error_message)."""
        import shutil
        path = shutil.which(binary_name)
        if path:
            return True, path
        return False, f"CLI Tool '{binary_name}' is not installed on system path. Please install via system package manager or use Python alternative."

