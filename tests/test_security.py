import unittest
import os
from tools.file_tools import is_safe_path
from tools.validation import ToolValidator

class TestSecurityValidation(unittest.TestCase):
    
    def test_path_traversal_blocked(self):
        # Ensure that paths trying to escape BASE_DIR are caught
        unsafe_path = "../../../etc/passwd"
        self.assertFalse(is_safe_path(unsafe_path))

    def test_ast_blocks_os_system(self):
        dangerous_code = "import os\nos.system('echo hacked')"
        violations = ToolValidator.validate_code(dangerous_code)
        self.assertTrue(any("os" in v for v in violations))
        self.assertTrue(any("system" in v for v in violations))

    def test_ast_blocks_subprocess(self):
        dangerous_code = "import subprocess\nsubprocess.Popen(['ls'])"
        violations = ToolValidator.validate_code(dangerous_code)
        self.assertTrue(any("subprocess" in v for v in violations))

    def test_ast_blocks_eval(self):
        dangerous_code = "x = eval('1 + 1')"
        violations = ToolValidator.validate_code(dangerous_code)
        self.assertTrue(any("eval" in v for v in violations))

if __name__ == '__main__':
    unittest.main()
