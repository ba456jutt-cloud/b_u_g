import unittest
from router.task_router import TaskRouter

class TestTaskRouter(unittest.TestCase):
    def setUp(self):
        self.router = TaskRouter()

    def test_cve_routing(self):
        task = "Tell me about CVE-2021-44228"
        self.assertEqual(self.router.route(task), "CVEResearchAgent")

    def test_code_review_routing(self):
        task = "Please review this Python code for vulnerabilities"
        self.assertEqual(self.router.route(task), "CodeReviewAgent")

    def test_knowledge_routing(self):
        task = "What is the OWASP Top 10?"
        self.assertEqual(self.router.route(task), "SecurityKnowledgeAgent")

    def test_vuln_analysis_routing(self):
        task = "Estimate severity of this XSS finding"
        self.assertEqual(self.router.route(task), "VulnerabilityAnalysisAgent")

    def test_report_routing(self):
        task = "Generate an executive summary report"
        self.assertEqual(self.router.route(task), "ReportAgent")

    def test_recon_routing(self):
        task = "Analyze these Nmap scan results"
        self.assertEqual(self.router.route(task), "ReconAnalysisAgent")

    def test_fallback_routing(self):
        task = "Do something generic"
        self.assertEqual(self.router.route(task), "BaseAgent")

if __name__ == '__main__':
    unittest.main()
