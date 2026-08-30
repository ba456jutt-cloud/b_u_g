from tools.base import Tool

class FindingsTool(Tool):
    name = "findings"
    description = "Processes and organizes security findings from various scans and assessments."
    parameters = {"target": "List of findings with details (finding, severity, impact, recommendation)"}

    def execute(self, target: list = None, **kwargs) -> str:
        try:
            if not target:
                return "Error: No findings provided."

            findings = []
            for finding in target:
                findings.append({
                    "finding": finding.get("finding", ""),
                    "severity": finding.get("severity", ""),
                    "impact": finding.get("impact", ""),
                    "recommendation": finding.get("recommendation", "")
                })

            # Sort findings by severity (Critical, High, Medium, Low, Info)
            severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
            findings.sort(key=lambda x: severity_order.get(x["severity"], 5))

            return {"findings": findings}
        except Exception as e:
            return f"Error: {str(e)}"