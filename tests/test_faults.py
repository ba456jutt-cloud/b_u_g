import unittest
import json
from tools.executor import ToolExecutor

class TestFaultInjection(unittest.TestCase):
    
    def setUp(self):
        from tools.registry import registry, ToolMetadata
        from tools.file_tools import ReadFileTool
        from tools.document_tools import ParseJSONTool
        
        registry.register(ReadFileTool, ToolMetadata(name="read_file", description="", parameters={}))
        registry.register(ParseJSONTool, ToolMetadata(name="parse_json", description="", parameters={}))

    def test_missing_file_recovery(self):
        # Attempt to read a file that doesn't exist
        result_json = ToolExecutor.execute("read_file", {"path": "/tmp/non_existent_file_123.txt"})
        result = json.loads(result_json)
        self.assertEqual(result["status"], "success")
        # Should gracefully return error string instead of crashing system
        self.assertTrue("Error: Access denied" in result["output"] or "No such file" in result["output"])

    def test_invalid_json_parsing(self):
        result_json = ToolExecutor.execute("parse_json", {"json_string": "{invalid json}"})
        result = json.loads(result_json)
        self.assertEqual(result["status"], "success") # Tool handled the exception internally
        self.assertTrue("Invalid JSON" in result["output"])

    def test_unregistered_tool(self):
        result_json = ToolExecutor.execute("fake_tool", {})
        result = json.loads(result_json)
        self.assertEqual(result["status"], "error")
        self.assertIn("not found in registry", result["output"])

if __name__ == '__main__':
    unittest.main()
