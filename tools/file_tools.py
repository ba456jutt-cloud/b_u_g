import os
import glob
from tools.base import Tool
from config.settings import settings

def is_safe_path(target_path: str) -> bool:
    """Prevents directory traversal attacks, restricts to BASE_DIR"""
    abs_target = os.path.abspath(target_path)
    return abs_target.startswith(settings.BASE_DIR)

class ReadFileTool(Tool):
    name = "read_file"
    def execute(self, path: str, **kwargs) -> str:
        if not is_safe_path(path): return "Error: Access denied."
        try:
            with open(path, 'r') as f: return f.read()
        except Exception as e: return str(e)

class WriteFileTool(Tool):
    name = "write_file"
    description = "Writes content to a specified local file path."
    parameters = {"path": "Local file path (e.g. /tmp/report.md)", "content": "Text content to write"}

    def execute(self, path: str = None, content: str = None, **kwargs) -> str:
        if not path:
            return "Error: Provide a valid file path."
        # Do NOT accept URLs as file path
        if path.startswith("http://") or path.startswith("https://"):
            return "Error: write_file expects a local file path, not a URL."
        try:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content or "")
            return f"Successfully wrote to {path}"
        except Exception as e:
            return f"Error writing file: {str(e)}"


class CreateDirectoryTool(Tool):
    name = "create_directory"
    def execute(self, path: str, **kwargs) -> str:
        if not is_safe_path(path): return "Error: Access denied."
        try:
            os.makedirs(path, exist_ok=True)
            return f"Directory {path} created."
        except Exception as e: return str(e)

class ListDirectoryTool(Tool):
    name = "list_directory"
    def execute(self, path: str, **kwargs) -> str:
        if not is_safe_path(path): return "Error: Access denied."
        try:
            return "\\n".join(os.listdir(path))
        except Exception as e: return str(e)

class SearchFilesTool(Tool):
    name = "search_files"
    def execute(self, pattern: str, directory: str = ".", **kwargs) -> str:
        target_dir = os.path.join(settings.BASE_DIR, directory)
        if not is_safe_path(target_dir): return "Error: Access denied."
        try:
            matches = glob.glob(os.path.join(target_dir, "**", pattern), recursive=True)
            return "\\n".join(matches) if matches else "No files found."
        except Exception as e: return str(e)
