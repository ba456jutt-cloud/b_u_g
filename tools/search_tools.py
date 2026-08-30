from tools.base import Tool
from knowledge.retrieval import RAGSearchTool
from memory.long_term_mem import LongTermMemoryDB
import json

class KnowledgeBaseSearchTool(Tool):
    name = "knowledge_base_search"
    def execute(self, query: str, **kwargs) -> str:
        # Wrapper around existing RAGSearchTool for the new ToolExecutor standard
        try:
            rag = RAGSearchTool()
            return rag.execute(query=query)
        except Exception as e:
            return f"Search failed: {str(e)}"

class MemorySearchTool(Tool):
    name = "memory_search"
    def execute(self, keyword: str, context: str = "project", **kwargs) -> str:
        try:
            db = LongTermMemoryDB()
            # Simple keyword search implementation for the DB
            cursor = db.conn.cursor()
            if context == "project":
                cursor.execute("SELECT id, key, value FROM project_memory WHERE key LIKE ? OR value LIKE ?", (f"%{keyword}%", f"%{keyword}%"))
            else:
                cursor.execute("SELECT id, note FROM user_notes WHERE note LIKE ?", (f"%{keyword}%",))
            
            results = cursor.fetchall()
            return json.dumps(results, indent=2) if results else "No memory found."
        except Exception as e:
            return f"Memory search failed: {str(e)}"
