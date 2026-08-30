import unittest
import json
from tools.registry import ToolRegistry, ToolMetadata
from tools.executor import ToolExecutor
from tools.validation import ToolValidator
from tools.base import Tool

class DummyTool(Tool):
    name = "dummy_tool"
    def execute(self, message: str, **kwargs) -> str:
        if message == "fail":
            raise ValueError("Intentional Failure")
        return f"Echo: {message}"

class TestToolsPhase(unittest.TestCase):
    def setUp(self):
        self.registry = ToolRegistry()
        meta = ToolMetadata(name="dummy_tool", description="A test tool", parameters={"message": "string"})
        self.registry.register(DummyTool, meta)

    def test_registry_metadata(self):
        self.assertIn("dummy_tool", self.registry.tools)
        self.assertEqual(self.registry.metadata["dummy_tool"].status, "active")

    def test_executor_success(self):
        result_json = ToolExecutor.execute("dummy_tool", {"message": "hello"})
        result = json.loads(result_json)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["output"], "Echo: hello")

    def test_executor_failure(self):
        result_json = ToolExecutor.execute("dummy_tool", {"message": "fail"})
        result = json.loads(result_json)
        self.assertEqual(result["status"], "error")
        self.assertIn("Intentional Failure", result["output"])

    def test_ast_validation_pass(self):
        safe_code = "def add(a, b): return a + b"
        violations = ToolValidator.validate_code(safe_code)
        self.assertEqual(len(violations), 0)

    def test_ast_validation_fail(self):
        dangerous_code = "import os\nos.system('rm -rf /')"
        violations = ToolValidator.validate_code(dangerous_code)
        self.assertTrue(len(violations) > 0)
        self.assertTrue(any("os" in v for v in violations))

if __name__ == '__main__':
    unittest.main()
