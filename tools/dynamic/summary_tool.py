from tools.base import Tool

class SummaryTool(Tool):
    name = "summary"
    description = "Synthesizes security findings and provides a comprehensive security assessment."
    parameters = {"target": "Description of security findings to summarize"}

    def execute(self, target: str, **kwargs) -> str:
        try:
            # Parse the input string to extract security findings
            findings = target.split('. ')
            
            # Categorize findings by severity
            critical = []
            high = []
            medium = []
            low = []
            
            for finding in findings:
                if finding.startswith("Critical:"):
                    critical.append(finding)
                elif finding.startswith("High:"):
                    high.append(finding)
                elif finding.startswith("Medium:"):
                    medium.append(finding)
                elif finding.startswith("Low:"):
                    low.append(finding)
            
            # Generate a detailed report
            report = {
                "Critical": critical,
                "High": high,
                "Medium": medium,
                "Low": low,
                "Recommendations": [
                    "Immediate firewall rule to block port 3306",
                    "Implement parameterized queries for search functionality",
                    "Add security headers and strengthen authentication controls",
                    "Update outdated libraries"
                ]
            }
            
            return str(report)
        except Exception as e:
            return f"[ERROR] Summary generation failed: {str(e)}"