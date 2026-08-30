from tools.base import Tool
import requests
import subprocess
import json
import os
from typing import Optional

class NextStepsTool(Tool):
    name = "next_steps"
    description = "Forward deduplicated findings to ReportAgent. Optionally gather HTTP headers and screenshots for evidence."
    parameters = {
        "target": "Target URL or IP address",
        "findings": "List of deduplicated findings to forward",
        "report_agent_url": "URL of the ReportAgent",
        "gather_evidence": "Boolean to indicate if evidence should be gathered"
    }

    def execute(self, target: str = None, findings: list = None, report_agent_url: str = None, gather_evidence: bool = False, **kwargs) -> str:
        try:
            # Validate input parameters
            if not target:
                return "Error: Target URL or IP address is required"
            if not findings:
                return "Error: Findings list is required"
            if not report_agent_url:
                return "Error: ReportAgent URL is required"

            # Prepare the payload for the ReportAgent
            payload = {
                "target": target,
                "findings": findings
            }

            # Gather evidence if requested
            if gather_evidence:
                evidence = self.gather_evidence(target)
                payload["evidence"] = evidence

            # Forward the findings to the ReportAgent
            headers = {"Content-Type": "application/json"}
            response = requests.post(report_agent_url, json=payload, headers=headers, timeout=30)
            response.raise_for_status()

            return json.dumps({"status": "success", "message": "Findings forwarded successfully", "response": response.json()})
        except requests.exceptions.RequestException as e:
            return json.dumps({"status": "error", "message": f"Failed to forward findings: {str(e)}"})
        except Exception as e:
            return json.dumps({"status": "error", "message": f"An unexpected error occurred: {str(e)}"})

    def gather_evidence(self, target: str) -> dict:
        evidence = {"headers": None, "screenshot": None}
        try:
            # Fetch HTTP headers
            response = requests.get(target, timeout=10)
            evidence["headers"] = dict(response.headers)

            # Take a screenshot using gowitness
            screenshot_path = f"/tmp/{target.replace('://', '_').replace('/', '_')}.png"
            cmd = ["gowitness", "single", "--no-headless", "-u", target, "-o", screenshot_path]
            subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if os.path.exists(screenshot_path):
                evidence["screenshot"] = screenshot_path

            return evidence
        except requests.exceptions.RequestException as e:
            return {"error": f"Failed to gather evidence: {str(e)}"}
        except subprocess.CalledProcessError as e:
            return {"error": f"Failed to take screenshot: {str(e)}"}
        except Exception as e:
            return {"error": f"An unexpected error occurred while gathering evidence: {str(e)}"}