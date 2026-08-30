from tools.base import Tool

class NucleiFindingsTool(Tool):
    name = "nuclei_findings"
    description = "Analyzes and categorizes vulnerabilities found by the nuclei scanner."
    parameters = {
        "critical": "Number of critical vulnerabilities",
        "high": "Number of high vulnerabilities",
        "medium": "Number of medium vulnerabilities",
        "low": "Number of low vulnerabilities",
        "info": "Number of informational findings",
        "vulnerabilities": "List of vulnerability findings from nuclei scans"
    }

    def execute(self, critical: int = 0, high: int = 0, medium: int = 0, low: int = 0, info: int = 0, vulnerabilities: list = None, **kwargs) -> str:
        if vulnerabilities is None:
            vulnerabilities = []

        # Initialize counters
        critical_count = critical
        high_count = high
        medium_count = medium
        low_count = low
        info_count = info

        # Categorize vulnerabilities
        for vuln in vulnerabilities:
            level = vuln.get('level', '').lower()
            if level == 'critical':
                critical_count += 1
            elif level == 'high':
                high_count += 1
            elif level == 'medium':
                medium_count += 1
            elif level == 'low':
                low_count += 1
            elif level == 'info':
                info_count += 1

        # Prepare the result
        result = {
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "info": info_count,
            "vulnerabilities": vulnerabilities
        }

        return str(result)