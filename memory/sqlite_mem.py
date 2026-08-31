import sqlite3
import json
import threading
from datetime import datetime
from config.settings import settings

# Thread-local storage for connections — each thread gets its own connection
_local = threading.local()

class MemoryDB:
    def __init__(self):
        self.db_path = settings.MEMORY_DB_PATH
        self._init_db()

    def _get_conn(self):
        """Return a thread-local SQLite connection with WAL mode and busy timeout enabled."""
        if not hasattr(_local, 'conn') or _local.conn is None:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA busy_timeout=5000;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            _local.conn = conn
        return _local.conn

    def _init_db(self):
        conn = self._get_conn()
        cursor = conn.cursor()

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS session_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            task TEXT,
            interaction TEXT
        )
        ''')

        # ── FIXED: task-scoped findings with UNIQUE(task_id, key) ──────────
        # Old: key TEXT UNIQUE  → cross-scan overwrites
        # New: UNIQUE(task_id, key) → each scan has its own isolated namespace
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS key_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id TEXT NOT NULL DEFAULT 'global',
            key TEXT NOT NULL,
            value TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(task_id, key)
        )
        ''')

        # Index for fast per-task lookups
        cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_findings_task_id ON key_findings(task_id)
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

        # Index for fast log streaming per task
        cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_exec_task_id ON execution_logs(task_id, id)
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

    # ────────────────────────────────────────────────────────────────────────
    # Task lifecycle helpers
    # ────────────────────────────────────────────────────────────────────────

    def cancel_task(self, task_id: str):
        """Mark a task as cancelled in DB."""
        conn = self._get_conn()
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

    def is_task_cancelled(self, task_id: str) -> bool:
        """Check if task has been cancelled."""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT 1 FROM cancelled_tasks WHERE task_id = ?",
            (task_id,)
        )
        row = cursor.fetchone()
        return row is not None

    def uncancel_task(self, task_id: str):
        """Remove task from cancelled_tasks DB table on resume."""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM cancelled_tasks WHERE task_id = ?", (task_id,))
        cursor.execute(
            "INSERT INTO execution_logs (task_id, agent_name, log_type, content) VALUES (?, ?, ?, ?)",
            (task_id, "System", "Status", "Task resumed by user from last saved checkpoint.")
        )
        conn.commit()

    # ────────────────────────────────────────────────────────────────────────
    # Checkpoints
    # ────────────────────────────────────────────────────────────────────────

    def save_checkpoint(self, task_id: str, task_name: str, completed_phases: list,
                        last_agent: str, context_data: dict = None):
        """Persist state checkpoint after each successful phase completion."""
        conn = self._get_conn()
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

    def get_checkpoint(self, task_id: str) -> dict:
        """Retrieve task checkpoint data for resumption."""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT task_name, completed_phases, last_agent, context_data, updated_at "
            "FROM task_checkpoints WHERE task_id = ?",
            (task_id,)
        )
        row = cursor.fetchone()
        if not row:
            return None
        return {
            "task_name": row[0],
            "completed_phases": json.loads(row[1]) if row[1] else [],
            "last_agent": row[2],
            "context_data": json.loads(row[3]) if row[3] else {},
            "updated_at": row[4]
        }

    # ────────────────────────────────────────────────────────────────────────
    # Reward / Reinforcement Learning
    # ────────────────────────────────────────────────────────────────────────

    def record_reward(self, agent_name: str, task_id: str, score_change: int, reason: str):
        """Record reward (+score) or penalty (-score) for an agent's execution quality."""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO agent_rewards (agent_name, task_id, score_change, reason) VALUES (?, ?, ?, ?)",
            (agent_name, task_id, score_change, reason)
        )
        conn.commit()

    def get_agent_performance_score(self, agent_name: str) -> dict:
        """Calculate total reward score, positive actions, penalties, and efficiency rating."""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT SUM(score_change), COUNT(id), "
            "SUM(CASE WHEN score_change > 0 THEN 1 ELSE 0 END), "
            "SUM(CASE WHEN score_change < 0 THEN 1 ELSE 0 END) "
            "FROM agent_rewards WHERE agent_name = ?",
            (agent_name,)
        )
        row = cursor.fetchone()

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

    # ────────────────────────────────────────────────────────────────────────
    # Self-Learning Reflections
    # ────────────────────────────────────────────────────────────────────────

    def save_reflection(self, agent_name: str, task_type: str, failed_action: str,
                        error_output: str, lesson: str):
        """Save a learned lesson from a failed action or tool error."""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO agent_reflections "
            "(agent_name, task_type, failed_action, error_output, lesson) VALUES (?, ?, ?, ?, ?)",
            (agent_name, task_type, str(failed_action)[:300],
             str(error_output)[:500], str(lesson)[:500])
        )
        conn.commit()

    def get_reflections(self, agent_name: str = None, limit: int = 5) -> list:
        """Fetch recent learned lessons to inject into prompt so agents don't repeat mistakes."""
        conn = self._get_conn()
        cursor = conn.cursor()
        if agent_name:
            cursor.execute(
                "SELECT agent_name, failed_action, error_output, lesson, timestamp "
                "FROM agent_reflections WHERE agent_name = ? ORDER BY id DESC LIMIT ?",
                (agent_name, limit)
            )
        else:
            cursor.execute(
                "SELECT agent_name, failed_action, error_output, lesson, timestamp "
                "FROM agent_reflections ORDER BY id DESC LIMIT ?",
                (limit,)
            )
        rows = cursor.fetchall()
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

    # ────────────────────────────────────────────────────────────────────────
    # Session Logs
    # ────────────────────────────────────────────────────────────────────────

    def log_interaction(self, task: str, interaction: dict):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO session_logs (task, interaction) VALUES (?, ?)",
            (task, json.dumps(interaction))
        )
        conn.commit()

    # ────────────────────────────────────────────────────────────────────────
    # Key Findings — TASK-SCOPED (FIXED: was globally unique, now per task)
    # ────────────────────────────────────────────────────────────────────────

    def save_finding(self, key: str, value: str, task_id: str = "global"):
        """Save a key finding scoped to a specific task_id.
        Multiple concurrent scans can store the same key without overwriting each other.
        """
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO key_findings (task_id, key, value) VALUES (?, ?, ?)",
            (task_id, key, str(value)[:10000])
        )
        conn.commit()

    def get_finding(self, key: str, task_id: str = "global") -> str:
        """Retrieve a finding for a specific task. Falls back to 'global' scope."""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT value FROM key_findings WHERE task_id = ? AND key = ?",
            (task_id, key)
        )
        result = cursor.fetchone()
        if result:
            return result[0]
        # Fallback to global scope for backward compatibility
        cursor.execute(
            "SELECT value FROM key_findings WHERE task_id = 'global' AND key = ?",
            (key,)
        )
        result = cursor.fetchone()
        return result[0] if result else None

    def get_findings_for_task(self, task_id: str, limit: int = 30) -> list:
        """Fetch all findings for a specific task — used for report generation."""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT key, value FROM key_findings WHERE task_id = ? ORDER BY id DESC LIMIT ?",
            (task_id, limit)
        )
        rows = cursor.fetchall()
        return [{"key": r[0], "value": r[1]} for r in rows]

    def get_all_findings(self, limit: int = 15, task_id: str = None) -> list:
        """Fetch stored key findings. If task_id provided, scoped to that task only."""
        conn = self._get_conn()
        cursor = conn.cursor()
        if task_id:
            cursor.execute(
                "SELECT key, value FROM key_findings WHERE task_id = ? ORDER BY id DESC LIMIT ?",
                (task_id, limit)
            )
        else:
            cursor.execute(
                "SELECT key, value FROM key_findings ORDER BY id DESC LIMIT ?",
                (limit,)
            )
        rows = cursor.fetchall()
        return [{"key": r[0], "value": r[1]} for r in rows]

    # ────────────────────────────────────────────────────────────────────────
    # Execution Logs
    # ────────────────────────────────────────────────────────────────────────

    def log_execution(self, task_id: str, agent_name: str, log_type: str, content: str):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO execution_logs (task_id, agent_name, log_type, content) VALUES (?, ?, ?, ?)",
            (task_id, agent_name, log_type, str(content)[:5000])
        )
        conn.commit()
