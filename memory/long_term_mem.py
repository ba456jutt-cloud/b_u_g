import sqlite3
import json
import logging
from datetime import datetime
from config.settings import settings

logger = logging.getLogger(__name__)

class LongTermMemoryDB:
    def __init__(self):
        self.db_path = settings.MEMORY_DB_PATH
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Phase 1 & 2 Tables
        cursor.execute('''CREATE TABLE IF NOT EXISTS session_logs (id INTEGER PRIMARY KEY, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, task TEXT, interaction TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS key_findings (id INTEGER PRIMARY KEY, key TEXT UNIQUE, value TEXT)''')
        
        # Phase 3 Advanced Tables
        cursor.execute('''CREATE TABLE IF NOT EXISTS project_memory (id INTEGER PRIMARY KEY, project_id TEXT, context TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS research_memory (id INTEGER PRIMARY KEY, topic TEXT, summary TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS user_notes (id INTEGER PRIMARY KEY, note TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')

        # Phase 4 Multi-Tenant Workspace & Findings Tables
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, hashed_password TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS projects (id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT, description TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY, project_id INTEGER, title TEXT, severity TEXT, description TEXT, tags TEXT, status TEXT DEFAULT 'Open', created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        
        conn.commit()
        conn.close()

    def save_research(self, topic: str, summary: str):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO research_memory (topic, summary) VALUES (?, ?)", (topic, summary))
        conn.commit()
        conn.close()
        logger.info(f"Saved research memory for topic: {topic}")

    def get_research(self, topic: str) -> str:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT summary FROM research_memory WHERE topic LIKE ?", (f"%{topic}%",))
        result = cursor.fetchall()
        conn.close()
        return "\n".join([r[0] for r in result]) if result else "No research found."

    def save_finding(self, key: str, value: str):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO key_findings (key, value) VALUES (?, ?)", (key, value))
        conn.commit()
        conn.close()

    def log_interaction(self, task: str, interaction: dict):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO session_logs (task, interaction) VALUES (?, ?)", (task, json.dumps(interaction)))
        conn.commit()
        conn.close()
