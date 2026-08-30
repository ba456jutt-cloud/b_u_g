import sqlite3
import json
from datetime import datetime
from config.settings import settings

class MemoryDB:
    def __init__(self):
        self.db_path = settings.MEMORY_DB_PATH
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS session_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            task TEXT,
            interaction TEXT
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS key_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE,
            value TEXT
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS execution_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            agent_name TEXT,
            log_type TEXT,
            content TEXT
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS agent_reflections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            agent_name TEXT,
            task_type TEXT,
            failed_action TEXT,
            error_output TEXT,
            lesson TEXT
        )
        ''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS agent_rewards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            agent_name TEXT,
            task_id TEXT,
            score_change INTEGER,
            reason TEXT
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS cancelled_tasks (
            task_id TEXT PRIMARY KEY,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS task_checkpoints (
            task_id TEXT PRIMARY KEY,
            task_name TEXT,
            completed_phases TEXT,
            last_agent TEXT,
            context_data TEXT,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')


        conn.commit()
        conn.close()


    def cancel_task(self, task_id: str):
        """Mark a task as cancelled in DB."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR IGNORE INTO cancelled_tasks (task_id) VALUES (?)",
            (task_id,)
        )
        cursor.execute(
            "INSERT INTO execution_logs (task_id, agent_name, log_type, content) VALUES (?, ?, ?, ?)",
            (task_id, "System", "Status", "Task cancelled by user.")
        )
        conn.commit()
        conn.close()

    def is_task_cancelled(self, task_id: str) -> bool:
        """Check if task has been cancelled."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT 1 FROM cancelled_tasks WHERE task_id = ?",
            (task_id,)
        )
        row = cursor.fetchone()
        conn.close()
        return row is not None

    def uncancel_task(self, task_id: str):
        """Remove task from cancelled_tasks DB table on resume."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM cancelled_tasks WHERE task_id = ?", (task_id,))
        cursor.execute(
            "INSERT INTO execution_logs (task_id, agent_name, log_type, content) VALUES (?, ?, ?, ?)",
            (task_id, "System", "Status", "Task resumed by user from last saved checkpoint.")
        )
        conn.commit()
        conn.close()


    def save_checkpoint(self, task_id: str, task_name: str, completed_phases: list, last_agent: str, context_data: dict = None):
        """Persist state checkpoint after each successful phase completion."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        phases_str = json.dumps(completed_phases)
        context_str = json.dumps(context_data or {})
        cursor.execute(
            """INSERT OR REPLACE INTO task_checkpoints 
               (task_id, task_name, completed_phases, last_agent, context_data, updated_at) 
               VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)""",
            (task_id, task_name, phases_str, last_agent, context_str)
        )
        conn.commit()
        conn.close()

    def get_checkpoint(self, task_id: str) -> dict:
        """Retrieve task checkpoint data for resumption."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT task_name, completed_phases, last_agent, context_data, updated_at FROM task_checkpoints WHERE task_id = ?", (task_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        return {
            "task_name": row[0],
            "completed_phases": json.loads(row[1]) if row[1] else [],
            "last_agent": row[2],
            "context_data": json.loads(row[3]) if row[3] else {},
            "updated_at": row[4]
        }



    def record_reward(self, agent_name: str, task_id: str, score_change: int, reason: str):
        """Record reward (+score) or penalty (-score) for an agent's execution quality."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO agent_rewards (agent_name, task_id, score_change, reason) VALUES (?, ?, ?, ?)",
            (agent_name, task_id, score_change, reason)
        )
        conn.commit()
        conn.close()

    def get_agent_performance_score(self, agent_name: str) -> dict:
        """Calculate total reward score, positive actions, penalties, and efficiency rating."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT SUM(score_change), COUNT(id), SUM(CASE WHEN score_change > 0 THEN 1 ELSE 0 END), SUM(CASE WHEN score_change < 0 THEN 1 ELSE 0 END) FROM agent_rewards WHERE agent_name = ?",
            (agent_name,)
        )
        row = cursor.fetchone()
        conn.close()
        
        total_score = row[0] if row and row[0] is not None else 0
        total_events = row[1] if row and row[1] is not None else 0
        pos_events = row[2] if row and row[2] is not None else 0
        neg_events = row[3] if row and row[3] is not None else 0
        
        efficiency = round((pos_events / total_events) * 100, 1) if total_events > 0 else 100.0
        return {
            "agent_name": agent_name,
            "total_score": total_score,
            "success_actions": pos_events,
            "penalties": neg_events,
            "efficiency_rate": efficiency
        }

    def save_reflection(self, agent_name: str, task_type: str, failed_action: str, error_output: str, lesson: str):
        """Save a learned lesson from a failed action or tool error."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO agent_reflections (agent_name, task_type, failed_action, error_output, lesson) VALUES (?, ?, ?, ?, ?)",
            (agent_name, task_type, str(failed_action)[:300], str(error_output)[:500], str(lesson)[:500])
        )
        conn.commit()
        conn.close()

    def get_reflections(self, agent_name: str = None, limit: int = 5) -> list:
        """Fetch recent learned lessons to inject into prompt so agents don't repeat mistakes."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        if agent_name:
            cursor.execute(
                "SELECT agent_name, failed_action, error_output, lesson, timestamp FROM agent_reflections WHERE agent_name = ? ORDER BY id DESC LIMIT ?",
                (agent_name, limit)
            )
        else:
            cursor.execute(
                "SELECT agent_name, failed_action, error_output, lesson, timestamp FROM agent_reflections ORDER BY id DESC LIMIT ?",
                (limit,)
            )
        rows = cursor.fetchall()
        conn.close()
        return [
            {
                "agent_name": r[0],
                "failed_action": r[1],
                "error_output": r[2],
                "lesson": r[3],
                "timestamp": r[4]
            }
            for r in rows
        ]

    def log_interaction(self, task: str, interaction: dict):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO session_logs (task, interaction) VALUES (?, ?)",
            (task, json.dumps(interaction))
        )
        conn.commit()
        conn.close()

    def save_finding(self, key: str, value: str):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO key_findings (key, value) VALUES (?, ?)",
            (key, value)
        )
        conn.commit()
        conn.close()

    def get_finding(self, key: str) -> str:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM key_findings WHERE key = ?", (key,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None

    def get_all_findings(self, limit: int = 15) -> list:
        """Fetch all stored key findings across previous scan steps to prevent state memory loss."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT key, value FROM key_findings ORDER BY id DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        conn.close()
        return [{"key": r[0], "value": r[1]} for r in rows]


    def log_execution(self, task_id: str, agent_name: str, log_type: str, content: str):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO execution_logs (task_id, agent_name, log_type, content) VALUES (?, ?, ?, ?)",
            (task_id, agent_name, log_type, content)
        )
        conn.commit()
        conn.close()
