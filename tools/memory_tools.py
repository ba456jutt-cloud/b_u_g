from tools.base import Tool
from memory.long_term_mem import LongTermMemoryDB

class SaveMemoryTool(Tool):
    name = "save_memory"
    description = "Saves a key-value pair to the long-term memory database."
    parameters = {"key": "The memory key", "value": "The value to save", "context": "Optional context string"}
    def execute(self, key: str, value: str, context: str = "project", **kwargs) -> str:
        try:
            import sqlite3
            from memory.long_term_mem import LongTermMemoryDB
            db = LongTermMemoryDB()
            
            conn = sqlite3.connect(db.db_path)
            cursor = conn.cursor()
            # If the schema changed to key_findings, use that, or just insert into key_findings
            cursor.execute("INSERT OR REPLACE INTO key_findings (key, value) VALUES (?, ?)", (key, value))
            conn.commit()
            conn.close()
            
            return f"Saved to memory: {key}"
        except Exception as e:
            return str(e)

class RetrieveMemoryTool(Tool):
    name = "retrieve_memory"
    description = "Retrieves a key-value pair from the long-term memory database."
    parameters = {"key": "The memory key to retrieve"}
    def execute(self, key: str, **kwargs) -> str:
        try:
            import sqlite3
            from memory.long_term_mem import LongTermMemoryDB
            db = LongTermMemoryDB()
            conn = sqlite3.connect(db.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM key_findings WHERE key = ?", (key,))
            row = cursor.fetchone()
            conn.close()
            return row[0] if row else "Key not found."
        except Exception as e:
            return str(e)
