"""
ioc_enrichment/rotator.py
--------------------------
API key rotation logic.

ApiKeyRotator is instantiated once per request and advances through a
pool of keys whenever the current one is rejected (HTTP 401 / 403 / 429).
Key state is intentionally per-request so concurrent calls never interfere
with each other.
"""

from __future__ import annotations
from src.logger import create_logger

logger = create_logger(__name__)


class ApiKeyRotator:
    """
    Manages a pool of API keys for a single enrichment request.

    Rotation policy
    ---------------
    * Keys are tried left-to-right.
    * Call ``rotate()`` when the current key is rejected.
    * Raises ``KeysExhaustedError`` once every key has been tried.
    """

    class KeysExhaustedError(Exception):
        """Raised when every key in the pool has been tried and failed."""

    # ------------------------------------------------------------------

    def __init__(self, keys: list[str]) -> None:
        if not keys:
            raise ValueError("ApiKeyRotator requires at least one API key.")
        self._keys:    list[str] = list(keys)
        self._index:   int       = 0
        self._failures: int      = 0

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def current_key(self) -> str:
        return self._keys[self._index]

    @property
    def keys_remaining(self) -> int:
        return len(self._keys) - self._index

    @property
    def failure_count(self) -> int:
        return self._failures

    # ------------------------------------------------------------------
    # Rotation
    # ------------------------------------------------------------------

    def rotate(self) -> str:
        """
        Advance to the next API key.

        Returns
        -------
        str
            The newly active key.

        Raises
        ------
        KeysExhaustedError
            When no further keys are available.
        """
        self._index    += 1
        self._failures += 1

        if self._index >= len(self._keys):
            raise self.KeysExhaustedError(
                f"All {len(self._keys)} API key(s) exhausted."
            )

        logger.warning(
            "API key rotated → key %d / %d",
            self._index + 1,
            len(self._keys),
        )
        return self.current_key


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    print("── ApiKeyRotator self-test ──")

    # Happy path: first key succeeds
    r = ApiKeyRotator(["aaa", "bbb", "ccc"])
    assert r.current_key == "aaa"
    assert r.keys_remaining == 3
    print("✓  initial key correct")

    # Rotation
    r.rotate()
    assert r.current_key == "bbb"
    assert r.keys_remaining == 2
    assert r.failure_count == 1
    print("✓  rotate() advances correctly")

    # Exhaustion
    r.rotate()   # → ccc
    try:
        r.rotate()   # → should raise
        print("✗  expected KeysExhaustedError was not raised")
        sys.exit(1)
    except ApiKeyRotator.KeysExhaustedError:
        print("✓  KeysExhaustedError raised when keys exhausted")

    # Empty key list
    try:
        ApiKeyRotator([])
        print("✗  expected ValueError for empty key list")
        sys.exit(1)
    except ValueError:
        print("✓  ValueError raised for empty key list")

    print("\nAll rotator tests passed.")