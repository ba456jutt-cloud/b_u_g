import os
import shutil
from tools.base import Tool
from tools.file_tools import is_safe_path

class CreateProjectTool(Tool):
    name = "create_project"
    def execute(self, project_name: str, **kwargs) -> str:
        # Create standard directory structure for a new engagement
        base = os.path.join(os.getcwd(), project_name)
        if not is_safe_path(base): return "Error: Access denied."
        try:
            dirs = ["recon", "vulns", "reports", "evidence"]
            for d in dirs:
                os.makedirs(os.path.join(base, d), exist_ok=True)
            return f"Project {project_name} initialized."
        except Exception as e: return str(e)

class ArchiveProjectTool(Tool):
    name = "archive_project"
    def execute(self, project_name: str, **kwargs) -> str:
        base = os.path.join(os.getcwd(), project_name)
        if not is_safe_path(base): return "Error: Access denied."
        try:
            shutil.make_archive(project_name, 'zip', base)
            return f"Project archived as {project_name}.zip"
        except Exception as e: return str(e)
