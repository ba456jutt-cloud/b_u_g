import ast
import logging

logger = logging.getLogger(__name__)

# Modules that are ALWAYS dangerous (no exceptions)
ALWAYS_BLOCKED_MODULES = {'shutil'}

# Modules allowed for security tools but need extra checks
SECURITY_ALLOWED_MODULES = {'subprocess', 'os', 'socket', 'ssl', 'urllib', 'http', 'requests', 'sys'}

# Absolute blocklist calls regardless of context
ABSOLUTE_BLOCKED_CALLS = {'eval', 'exec', '__import__', 'compile', 'open_channel'}

# Destructive patterns
DESTRUCTIVE_COMMANDS = ['rm -rf', 'mkfs', 'fdisk', 'dd if=', 'format c:', '> /dev/sd', 'chmod 777 /', 'del /f /s /q']


class SecurityScanner(ast.NodeVisitor):
    def __init__(self, allow_security_modules: bool = True):
        self.violations = []
        self.warnings = []
        self.allow_security_modules = allow_security_modules

    def visit_Import(self, node):
        for alias in node.names:
            module = alias.name.split('.')[0]
            if module in ALWAYS_BLOCKED_MODULES:
                self.violations.append(f"Disallowed import: {alias.name}")
            elif module in SECURITY_ALLOWED_MODULES and not self.allow_security_modules:
                self.violations.append(f"Disallowed import (not in security mode): {alias.name}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            module = node.module.split('.')[0]
            if module in ALWAYS_BLOCKED_MODULES:
                self.violations.append(f"Disallowed from import: {node.module}")
        self.generic_visit(node)

    def visit_Call(self, node):
        # Block absolute dangerous calls
        if isinstance(node.func, ast.Name):
            if node.func.id in ABSOLUTE_BLOCKED_CALLS:
                self.violations.append(f"Disallowed function call: {node.func.id}")
        elif isinstance(node.func, ast.Attribute):
            if node.func.attr in ABSOLUTE_BLOCKED_CALLS:
                self.violations.append(f"Disallowed method call: {node.func.attr}")
        self.generic_visit(node)

    def visit_Constant(self, node):
        # Check for destructive shell commands in string constants
        if isinstance(node.value, str):
            for pattern in DESTRUCTIVE_COMMANDS:
                if pattern in node.value.lower():
                    self.violations.append(f"Destructive command pattern detected in string: '{pattern}'")
        self.generic_visit(node)


class ToolValidator:
    @staticmethod
    def validate_code(python_code: str, allow_security_modules: bool = True) -> list:
        """
        Statically analyzes Python code for dangerous patterns.
        Security tools are allowed to use subprocess, os, socket etc.
        Returns list of violations. Empty = passed.
        """
        if not python_code or not python_code.strip():
            return ["Empty code provided"]

        try:
            tree = ast.parse(python_code)
        except SyntaxError as e:
            return [f"Syntax Error: {str(e)}"]

        scanner = SecurityScanner(allow_security_modules=allow_security_modules)
        scanner.visit(tree)
        return scanner.violations

    @staticmethod
    def extract_class_name(python_code: str) -> str:
        """Extract the main Tool class name from generated code."""
        try:
            tree = ast.parse(python_code)
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    return node.name
        except Exception:
            pass
        return "DynamicTool"
