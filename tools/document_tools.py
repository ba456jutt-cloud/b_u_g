import json
from pypdf import PdfReader
from tools.base import Tool
from tools.file_tools import is_safe_path

class ReadPDFTool(Tool):
    name = "read_pdf"
    def execute(self, path: str, **kwargs) -> str:
        if not is_safe_path(path): return "Error: Access denied."
        try:
            reader = PdfReader(path)
            text = ""
            for page in reader.pages:
                text += page.extract_text() + "\\n"
            return text
        except Exception as e: return str(e)

class ReadMarkdownTool(Tool):
    name = "read_markdown"
    def execute(self, path: str, **kwargs) -> str:
        if not is_safe_path(path): return "Error: Access denied."
        try:
            with open(path, 'r') as f: return f.read()
        except Exception as e: return str(e)

class ParseJSONTool(Tool):
    name = "parse_json"
    def execute(self, json_string: str, **kwargs) -> str:
        try:
            data = json.loads(json_string)
            return json.dumps(data, indent=2)
        except Exception as e: return f"Invalid JSON: {str(e)}"
