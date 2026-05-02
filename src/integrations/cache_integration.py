"""
ioc_enrichment/cache_integration.py
------------------------------------
Extended base class with SQLite caching for IOC enrichment integrations.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

import httpx

from src.logger import create_logger
from src.integrations.models import ArtifactType, EnrichmentResult
from src.integrations.base_integration import BaseIntegration


class CachedIntegration(BaseIntegration):
    """
    Extended base integration with SQLite caching.
    
    Caches API responses with configurable TTL (default 7 days).
    Cache table name = integration name (sanitized for SQLite).
    """

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        
        # Cache configuration
        self.cache_dir = Path(config.get("cache_dir", "data/cache"))
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.cache_db_path = self.cache_dir / "ioc_cache.db"
        self.retention_days = int(config.get("cache_retention_days", 7))
        
        # Table name from integration name (sanitize for SQLite)
        self.table_name = self._sanitize_table_name(self.name)
        
        # Initialize cache database
        self._init_cache_db()
        
        self._cache_log = create_logger(f"cache.{self.name}")

    def _sanitize_table_name(self, name: str) -> str:
        """Sanitize integration name for SQLite table identifier."""
        # Replace invalid characters with underscore
        invalid_chars = ' -./\\()[]{}!@#$%^&*+=;:\'",<>?|`~'
        for char in invalid_chars:
            name = name.replace(char, '_')
        # Ensure starts with letter or underscore
        if name[0].isdigit():
            name = f"_{name}"
        # Limit length
        return name[:64]

    def _init_cache_db(self) -> None:
        """Initialize cache database and create table if not exists."""
        with sqlite3.connect(self.cache_db_path) as conn:
            conn.execute(f"""
                CREATE TABLE IF NOT EXISTS "{self.table_name}" (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    artifact TEXT NOT NULL,
                    artifact_type TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    data TEXT,
                    error TEXT,
                    api_key_used TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(artifact, artifact_type)
                )
            """)
            conn.execute(f"""
                CREATE INDEX IF NOT EXISTS idx_{self.table_name}_artifact 
                ON "{self.table_name}"(artifact, artifact_type)
            """)
            conn.execute(f"""
                CREATE INDEX IF NOT EXISTS idx_{self.table_name}_updated 
                ON "{self.table_name}"(updated_at)
            """)
            conn.commit()

    def _get_cached_entry(
        self, 
        artifact: str, 
        artifact_type: ArtifactType
    ) -> Optional[dict[str, Any]]:
        """
        Retrieve cached entry if exists and not expired.
        
        Returns None if:
        - Entry doesn't exist
        - Entry is expired (> retention_days old)
        """
        cutoff_time = datetime.now() - timedelta(days=self.retention_days)
        
        with sqlite3.connect(self.cache_db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(f"""
                SELECT artifact, artifact_type, success, data, error, 
                       api_key_used, created_at, updated_at
                FROM "{self.table_name}"
                WHERE artifact = ? AND artifact_type = ?
            """, (artifact, artifact_type.value))
            
            row = cursor.fetchone()
            
            if row:
                updated_at = datetime.fromisoformat(row["updated_at"])
                
                # Check if cache is expired
                if updated_at < cutoff_time:
                    self._cache_log.info(
                        "Cache expired for %s:%s (updated: %s > %s days)",
                        artifact_type.value, artifact, 
                        row["updated_at"], self.retention_days
                    )
                    return None
                
                self._cache_log.info(
                    "Cache HIT for %s:%s (age: %s days)",
                    artifact_type.value, artifact,
                    (datetime.now() - updated_at).days
                )
                return dict(row)
            
            self._cache_log.info("Cache MISS for %s:%s", artifact_type.value, artifact)
            return None

    def _store_cached_entry(
        self,
        artifact: str,
        artifact_type: ArtifactType,
        result: EnrichmentResult,
    ) -> None:
        """Store or update cache entry."""
        with sqlite3.connect(self.cache_db_path) as conn:
            # Use UPSERT pattern (INSERT OR REPLACE for simplicity)
            conn.execute(f"""
                INSERT OR REPLACE INTO "{self.table_name}" 
                (artifact, artifact_type, success, data, error, api_key_used, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (
                artifact,
                artifact_type.value,
                1 if result.success else 0,
                json.dumps(result.data) if result.data else None,
                result.error,
                result.api_key_used,
            ))
            conn.commit()
            self._cache_log.debug("Cached result for %s:%s", artifact_type.value, artifact)

    def _prune_old_entries(self) -> int:
        """Remove entries older than retention_days. Returns count removed."""
        cutoff_time = datetime.now() - timedelta(days=self.retention_days)
        
        with sqlite3.connect(self.cache_db_path) as conn:
            cursor = conn.execute(f"""
                DELETE FROM "{self.table_name}"
                WHERE updated_at < ?
            """, (cutoff_time.isoformat(),))
            conn.commit()
            removed = cursor.rowcount
            
            if removed > 0:
                self._cache_log.info("Pruned %d expired cache entries", removed)
            return removed

    def _maintain_cache(self) -> None:
        """Optional: Run cache maintenance periodic cleanup."""
        try:
            self._prune_old_entries()
        except Exception as e:
            self._cache_log.warning("Cache maintenance failed: %s", e)

    # Override the main entry point with caching
    async def start(
        self,
        artifact: str,
        artifact_type: ArtifactType | str,
    ) -> EnrichmentResult:
        """
        Run enrichment with caching - check cache first, API on miss.
        """
        if isinstance(artifact_type, str):
            artifact_type = ArtifactType(artifact_type)

        t0 = time.monotonic()
        
        # Run maintenance periodically (optional: add random sampling)
        self._maintain_cache()
        
        # Check cache first
        cached = self._get_cached_entry(artifact, artifact_type)
        
        if cached:
            # Return cached result
            result = EnrichmentResult(
                integration=self.name,
                artifact=cached["artifact"],
                artifact_type=ArtifactType(cached["artifact_type"]),
                success=bool(cached["success"]),
                data=json.loads(cached["data"]) if cached["data"] else None,
                error=cached["error"],
                api_key_used=cached["api_key_used"],
                cached=True,  # You'll need to add this field to EnrichmentResult
            )
            result.elapsed = time.monotonic() - t0
            return result
        
        # Cache miss - call API via parent method
        try:
            result = await self._execute_with_rotation(artifact, artifact_type)
            
            # Store successful (and optionally failed) results in cache
            if result.success or self._cache_failed_results():
                self._store_cached_entry(artifact, artifact_type, result)
                
        except Exception as exc:
            result = EnrichmentResult(
                integration=self.name,
                artifact=artifact,
                artifact_type=artifact_type,
                success=False,
                error=f"Unhandled exception: {exc}",
            )
        
        result.elapsed = time.monotonic() - t0
        return result
    
    def _cache_failed_results(self) -> bool:
        """Override to control whether failed results are cached."""
        return False  # Don't cache errors by default


# Utility mixin for additional cache management
class CacheManagementMixin:
    """Add cache management utilities to any integration."""
    
    async def clear_cache(self, artifact: Optional[str] = None) -> int:
        """Clear cache for specific artifact or all."""
        if not hasattr(self, 'table_name') or not hasattr(self, 'cache_db_path'):
            raise AttributeError("Cache not initialized")
        
        with sqlite3.connect(self.cache_db_path) as conn:
            if artifact:
                cursor = conn.execute(f"""
                    DELETE FROM "{self.table_name}"
                    WHERE artifact = ?
                """, (artifact,))
            else:
                cursor = conn.execute(f'DELETE FROM "{self.table_name}"')
            conn.commit()
            return cursor.rowcount
    
    async def get_cache_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        if not hasattr(self, 'table_name') or not hasattr(self, 'cache_db_path'):
            raise AttributeError("Cache not initialized")
        
        with sqlite3.connect(self.cache_db_path) as conn:
            cursor = conn.execute(f"""
                SELECT 
                    COUNT(*) as total_entries,
                    COUNT(CASE WHEN success = 1 THEN 1 END) as successful,
                    COUNT(CASE WHEN success = 0 THEN 1 END) as failed,
                    MIN(updated_at) as oldest,
                    MAX(updated_at) as newest
                FROM "{self.table_name}"
            """)
            row = cursor.fetchone()
            
            return {
                "total_entries": row[0],
                "successful": row[1],
                "failed": row[2],
                "oldest_entry": row[3],
                "newest_entry": row[4],
                "retention_days": self.retention_days,
            }