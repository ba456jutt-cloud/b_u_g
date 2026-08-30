import unittest
from unittest.mock import MagicMock
from agents.vulnerability_analysis_agent import VulnerabilityAnalysisAgent
import json

class TestAgents(unittest.TestCase):
    def setUp(self):
        self.mock_llm = MagicMock()
        self.mock_memory = MagicMock()
        self.mock_router = MagicMock()
        self.mock_router.route.return_value = "VulnerabilityAnalysisAgent"

    def test_vulnerability_analysis_output_format(self):
        # Setup mock LLM response
        expected_json_output = {
            "finding": "Test finding",
            "severity": "High",
            "impact": "Data loss",
            "recommendation": "Fix it"
        }
        
        # The agent expects the final result to just be the dictionary in 'result' if action is 'none',
        # but VulnerabilityAnalysisAgent expects the final_output string to be the parsed JSON directly 
        # or for the LLM to output the JSON string as the result.
        
        # Mocking the base agent's LLM generation to return action none and the JSON string as result
        self.mock_llm.generate.return_value = {
            "action": "none",
            "result": json.dumps(expected_json_output)
        }

        agent = VulnerabilityAnalysisAgent(
            llm_provider=self.mock_llm,
            memory=self.mock_memory,
            router=self.mock_router,
            tools=[]
        )

        result = agent.run("Analyze this test finding")
        
        # Check that memory was called to save the finding
        self.assertTrue(self.mock_memory.save_finding.called)
        
        # Check output is valid JSON
        parsed_result = json.loads(result)
        self.assertEqual(parsed_result["severity"], "High")

if __name__ == '__main__':
    unittest.main()
