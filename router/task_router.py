class TaskRouter:
    def route(self, task: str) -> str:
        """
        Deterministic router for Phase 2.
        Routes tasks to specialized agents based on keyword matching.
        """
        task_lower = task.lower()
        
        if any(kw in task_lower for kw in ["cve", "vulnerability database", "mitre"]):
            return "CVEResearchAgent"
            
        elif any(kw in task_lower for kw in ["review", "code", "sast", "source"]):
            return "CodeReviewAgent"
            
        elif any(kw in task_lower for kw in ["owasp", "best practice", "how to secure", "cwe explanation", "guidance"]):
            return "SecurityKnowledgeAgent"
            
        elif any(kw in task_lower for kw in ["analyze finding", "severity", "impact", "business impact", "estimate severity"]):
            return "VulnerabilityAnalysisAgent"
            
        elif any(kw in task_lower for kw in ["report", "executive summary", "remediation plan"]):
            return "ReportAgent"
            
        elif any(kw in task_lower for kw in ["recon", "scan results", "nmap", "technologies", "endpoints", "headers", "http://", "https://", "website"]):
            return "ReconAnalysisAgent"
            
        elif any(kw in task_lower for kw in ["read", "write", "file", "save"]):
            return "file_task" # Fallback to base agent behaviors
            
        elif any(kw in task_lower for kw in ["run", "execute", "command", "ls", "pwd", "whoami"]):
            return "system_task" # Fallback to base agent behaviors
            
        else:
            return "BaseAgent"
