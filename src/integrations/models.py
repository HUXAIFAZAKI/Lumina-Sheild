"""
ioc_enrichment/models.py
------------------------
Shared data types used across the entire enrichment system.

  ArtifactType    — enum of supported IOC categories
  EnrichmentResult — uniform response envelope returned by every integration
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Artifact type
# ---------------------------------------------------------------------------

class ArtifactType(str, Enum):
    IP     = "ip"
    DOMAIN = "domain"
    URL    = "url"
    HASH   = "hash"


# ---------------------------------------------------------------------------
# HTTP status codes that trigger API key rotation
# ---------------------------------------------------------------------------

ROTATE_ON: frozenset[int] = frozenset({401, 403, 429})


# ---------------------------------------------------------------------------
# Result envelope
# ---------------------------------------------------------------------------

@dataclass
class EnrichmentResult:
    """
    Uniform response envelope returned by every integration.

    Attributes
    ----------
    integration   : Name of the integration that produced this result.
    artifact      : The IOC that was queried.
    artifact_type : Category of the IOC.
    success       : True when data was retrieved without error.
    data          : Raw API response payload (None on failure).
    error         : Human-readable error description (None on success).
    elapsed       : Wall-clock seconds the lookup took.
    api_key_used  : Last-4-chars-masked key that ultimately succeeded.
    """

    integration:   str
    artifact:      str
    artifact_type: ArtifactType
    success:       bool
    data:          dict[str, Any] | None = None
    error:         str | None            = None
    elapsed:       float                 = 0.0
    api_key_used:  str | None            = None
    cached: bool = False

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def mask_key(key: str | None) -> str | None:
        """Return a masked version of an API key (last 4 chars visible)."""
        if not key or len(key) < 5:
            return key
        return f"{'*' * (len(key) - 4)}{key[-4:]}"

    def __repr__(self) -> str:
        status = "✓" if self.success else "✗"
        return (
            f"EnrichmentResult({status} {self.integration} | "
            f"{self.artifact_type.value}:{self.artifact} | "
            f"{self.elapsed:.2f}s)"
        )