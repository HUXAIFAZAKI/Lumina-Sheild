"""
Persistent SQLite-backed disk cache with TTL for expensive API/LLM calls.
Survives Streamlit restarts unlike st.cache_data (in-memory only).
"""
import sqlite3
import json
import hashlib
import time
import os
import pathlib
import threading

_DB_PATH = pathlib.Path(__file__).parent.parent / "data" / "lumina_cache.db"
_lock = threading.Lock()


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cache (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            expires_at REAL NOT NULL,
            created_at REAL NOT NULL,
            hits INTEGER DEFAULT 0,
            namespace TEXT DEFAULT 'default'
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_expires ON cache(expires_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_namespace ON cache(namespace)")
    conn.commit()
    return conn


def _make_key(namespace: str, *args) -> str:
    raw = namespace + ":" + ":".join(str(a) for a in args)
    return hashlib.sha256(raw.encode()).hexdigest()


def cache_get(namespace: str, *args):
    """Return cached value or None if missing/expired."""
    key = _make_key(namespace, *args)
    try:
        with _lock:
            conn = _get_conn()
            row = conn.execute(
                "SELECT value, expires_at FROM cache WHERE key=?", (key,)
            ).fetchone()
            if row:
                if row[1] > time.time():
                    conn.execute("UPDATE cache SET hits=hits+1 WHERE key=?", (key,))
                    conn.commit()
                    conn.close()
                    return json.loads(row[0])
                else:
                    # Expired — evict
                    conn.execute("DELETE FROM cache WHERE key=?", (key,))
                    conn.commit()
            conn.close()
    except Exception:
        pass
    return None


def cache_set(namespace: str, value, ttl_seconds: int, *args):
    """Store value in cache with TTL."""
    key = _make_key(namespace, *args)
    try:
        with _lock:
            conn = _get_conn()
            conn.execute(
                """INSERT OR REPLACE INTO cache(key, value, expires_at, created_at, namespace)
                   VALUES (?, ?, ?, ?, ?)""",
                (key, json.dumps(value, default=str), time.time() + ttl_seconds, time.time(), namespace)
            )
            conn.commit()
            conn.close()
    except Exception:
        pass


def cache_stats() -> dict:
    """Return cache hit/miss statistics per namespace."""
    try:
        with _lock:
            conn = _get_conn()
            rows = conn.execute(
                "SELECT namespace, COUNT(*) as entries, SUM(hits) as total_hits FROM cache WHERE expires_at > ? GROUP BY namespace",
                (time.time(),)
            ).fetchall()
            conn.close()
            return {r[0]: {"entries": r[1], "total_hits": r[2] or 0} for r in rows}
    except Exception:
        return {}


def cache_purge_expired():
    """Remove all expired entries."""
    try:
        with _lock:
            conn = _get_conn()
            deleted = conn.execute("DELETE FROM cache WHERE expires_at <= ?", (time.time(),)).rowcount
            conn.commit()
            conn.close()
            return deleted
    except Exception:
        return 0


def cache_clear_namespace(namespace: str):
    """Clear all entries for a specific namespace."""
    try:
        with _lock:
            conn = _get_conn()
            conn.execute("DELETE FROM cache WHERE namespace=?", (namespace,))
            conn.commit()
            conn.close()
    except Exception:
        pass


def cached(namespace: str, ttl_seconds: int):
    """Decorator: @cached('my_namespace', 3600) def my_func(arg): ..."""
    def decorator(fn):
        def wrapper(*args, **kwargs):
            cache_key_args = args + tuple(sorted(kwargs.items()))
            result = cache_get(namespace, *cache_key_args)
            if result is not None:
                return result
            result = fn(*args, **kwargs)
            if result is not None:
                cache_set(namespace, result, ttl_seconds, *cache_key_args)
            return result
        return wrapper
    return decorator
