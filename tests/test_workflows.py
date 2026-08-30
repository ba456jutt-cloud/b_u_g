import unittest
from unittest.mock import MagicMock
from workflows.engine import WorkflowEngine

class TestWorkflowEngine(unittest.TestCase):
    def setUp(self):
        self.mock_code_agent = MagicMock()
        self.mock_code_agent.run.return_value = "Code Reviewed"
        
        self.mock_vuln_agent = MagicMock()
        self.mock_vuln_agent.run.return_value = "Vulnerability Assessed"
        
        self.agents = {
            "CodeReviewAgent": self.mock_code_agent,
            "VulnerabilityAnalysisAgent": self.mock_vuln_agent
        }
        self.engine = WorkflowEngine(self.agents)

    def test_workflow_execution(self):
        steps = ["CodeReviewAgent", "VulnerabilityAnalysisAgent"]
        result = self.engine.run_workflow("Test Workflow", "Initial Data", steps)
        
        self.mock_code_agent.run.assert_called_once_with("Initial Data")
        self.mock_vuln_agent.run.assert_called_once_with("Code Reviewed")
        self.assertEqual(result, "Vulnerability Assessed")

    def test_missing_agent(self):
        steps = ["MissingAgent"]
        result = self.engine.run_workflow("Error Workflow", "Data", steps)
        self.assertTrue(result.startswith("Workflow Error"))

if __name__ == '__main__':
    unittest.main()
