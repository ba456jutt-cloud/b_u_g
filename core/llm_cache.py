"""
LLM Response Cache — SQLite-backed.
Prevents burning free-tier quota by caching identical prompts.
TTL default = 3600 seconds (1 hour). Identical prompts reuse cached response.
"""
import sqlite3
import hashlib
import json
import time
import os
import logging

logger = logging.getLogger(__name__)

_DB_PATH = os.path.join(os.path.dirname(__file__), "..", "memory", "llm_cache.db")
_TTL = int(os.getenv("LLM_CACHE_TTL", "3600"))  # 1 hour default


def _get_conn():
    conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS llm_cache (
            prompt_hash TEXT PRIMARY KEY,
            response    TEXT NOT NULL,
            created_at  REAL NOT NULL
        )
    """)
    conn.commit()
    return conn


def _hash_prompt(prompt: str) -> str:
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


def get_cached(prompt: str) -> dict | None:
    """Return cached dict response or None if not found / expired."""
    try:
        conn = _get_conn()
        h = _hash_prompt(prompt)
        row = conn.execute(
            "SELECT response, created_at FROM llm_cache WHERE prompt_hash = ?", (h,)
        ).fetchone()
        conn.close()
        if row:
            response_text, created_at = row
            if time.time() - created_at < _TTL:
                logger.info(f"[LLMCache] HIT — returning cached response (hash={h[:8]})")
                return json.loads(response_text)
    except Exception as e:
        logger.warning(f"[LLMCache] Cache read error: {e}")
    return None


def set_cached(prompt: str, response: dict):
    """Store a response in the cache."""
    try:
        conn = _get_conn()
        h = _hash_prompt(prompt)
        conn.execute(
            "INSERT OR REPLACE INTO llm_cache (prompt_hash, response, created_at) VALUES (?, ?, ?)",
            (h, json.dumps(response), time.time())
        )
        conn.commit()
        conn.close()
        logger.info(f"[LLMCache] STORED — cached response (hash={h[:8]})")
    except Exception as e:
        logger.warning(f"[LLMCache] Cache write error: {e}")


def clear_expired():
    """Purge entries older than TTL."""
    try:
        conn = _get_conn()
        cutoff = time.time() - _TTL
        deleted = conn.execute(
            "DELETE FROM llm_cache WHERE created_at < ?", (cutoff,)
        ).rowcount
        conn.commit()
        conn.close()
        if deleted:
            logger.info(f"[LLMCache] Purged {deleted} expired entries.")
    except Exception as e:
        logger.warning(f"[LLMCache] Purge error: {e}")
