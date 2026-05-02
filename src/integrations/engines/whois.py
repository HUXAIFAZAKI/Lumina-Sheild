"""
src/integrations/engines/whois.py
----------------------------------
WHOIS enrichment integration.

Artifact handling
-----------------
  domain → python-whois  (whois.whois)
  ip     → ipwhois       (IPWhois.lookup_rdap)
  url    → domain extracted from URL, then treated as domain
  hash   → skipped  (returns success=True with data=None and a notice)

This integration does NOT use HTTP APIs, API keys, or the base retry/
rotation machinery.  It overrides ``start()`` directly and delegates
to blocking WHOIS calls run inside asyncio's thread-pool executor so
the event loop is never blocked.

Dependencies
------------
    pip install python-whois ipwhois

Run standalone
--------------
    python -m src.integrations.engines.whois
"""

from __future__ import annotations

import asyncio
import time
import urllib.parse
from typing import Any
import validators

from src.integrations.engines.base import BaseIntegration
from src.integrations.models import ArtifactType, EnrichmentResult
from src.logger import create_logger

logger = create_logger()

# ---------------------------------------------------------------------------
# Optional dependency guards — fail loudly at import time with a clear message
# ---------------------------------------------------------------------------
try:
    import whois as python_whois          # python-whois
except ImportError as _e:
    raise ImportError(
        "python-whois is required for WhoisIntegration.  "
        "Install it with: pip install python-whois"
    ) from _e

try:
    from ipwhois import IPWhois           # ipwhois
except ImportError as _e:
    raise ImportError(
        "ipwhois is required for WhoisIntegration.  "
        "Install it with: pip install ipwhois"
    ) from _e


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_derived_from_url(url: str) -> str:
    """
    Pull the bare hostname out of a URL string.

    Examples
    --------
    >>> _extract_derived_from_url("https://sub.example.com/path?q=1")
    'sub.example.com'
    """
    parsed = urllib.parse.urlparse(url)
    host   = parsed.hostname or parsed.netloc
    # Strip port if present (urlparse may leave it in netloc)
    return host.split(":")[0].lower().strip()


def _whois_domain(domain: str) -> dict[str, Any]:
    """
    Perform a WHOIS lookup for *domain* and return a clean dict.

    python-whois returns a ``Who`` object with attributes that may be
    single values or lists; we normalise everything to plain Python types.
    """
    result = python_whois.whois(domain)

    def _serialise(value: Any) -> Any:
        """Recursively convert non-JSON-safe types to strings."""
        if value is None:
            return None
        if isinstance(value, list):
            return [_serialise(v) for v in value]
        if isinstance(value, dict):
            return {k: _serialise(v) for k, v in value.items()}
        # datetime objects, etc.
        return str(value) if not isinstance(value, (str, int, float, bool)) else value

    raw: dict[str, Any] = dict(result)
    return {k: _serialise(v) for k, v in raw.items() if v is not None}


def _whois_ip(ip: str) -> dict[str, Any]:
    """
    Perform an RDAP/WHOIS lookup for *ip* and return a clean dict.

    Uses ipwhois RDAP by default (richer, structured data);
    falls back to legacy WHOIS if RDAP is unavailable.
    """
    obj = IPWhois(ip)
    try:
        return obj.lookup_rdap(depth=1)
    except Exception:
        logger.warning("RDAP failed for %s — falling back to legacy WHOIS", ip)
        return obj.lookup_whois()


# ---------------------------------------------------------------------------
# Integration class
# ---------------------------------------------------------------------------

class WhoisIntegration(BaseIntegration):
    """
    WHOIS / RDAP enrichment integration.

    Unlike HTTP-based integrations this class:
      - Has no API keys (pass ``"apis": []`` in config).
      - Overrides ``start()`` directly — bypasses the HTTP retry machinery.
      - Runs blocking library calls in asyncio's thread-pool executor.
    """

    # ------------------------------------------------------------------
    # Entry-point override  (replaces the HTTP retry loop entirely)
    # ------------------------------------------------------------------

    async def start(
        self,
        artifact:      str,
        artifact_type: ArtifactType | str,
    ) -> EnrichmentResult:
        if isinstance(artifact_type, str):
            artifact_type = ArtifactType(artifact_type)

        t0 = time.monotonic()

        # ── Skip unsupported types gracefully ──────────────────────────
        if artifact_type == ArtifactType.HASH:
            return EnrichmentResult(
                integration=self.name,
                artifact=artifact,
                artifact_type=artifact_type,
                success=True,
                data=None,
                error=None,
                elapsed=time.monotonic() - t0,
                api_key_used=None,
            )

        try:
            data = await self._resolve(artifact, artifact_type)
        except Exception as exc:
            logger.error("WhoisIntegration error for %s: %s", artifact, exc)
            return EnrichmentResult(
                integration=self.name,
                artifact=artifact,
                artifact_type=artifact_type,
                success=False,
                error=str(exc),
                elapsed=time.monotonic() - t0,
            )

        return EnrichmentResult(
            integration=self.name,
            artifact=artifact,
            artifact_type=artifact_type,
            success=True,
            data=data,
            elapsed=time.monotonic() - t0,
        )

    # ------------------------------------------------------------------
    # Internal dispatch
    # ------------------------------------------------------------------

    async def _resolve(
        self,
        artifact:      str,
        artifact_type: ArtifactType,
    ) -> dict[str, Any]:
        """
        Route to the correct lookup function and run it off the event loop.
        """
        loop = asyncio.get_running_loop()

        match artifact_type:
            case ArtifactType.DOMAIN:
                logger.info("WHOIS domain lookup: %s", artifact)
                return await loop.run_in_executor(None, _whois_domain, artifact)

            case ArtifactType.IP:
                logger.info("WHOIS IP lookup: %s", artifact)
                return await loop.run_in_executor(None, _whois_ip, artifact)

            case ArtifactType.URL:
                domain = _extract_derived_from_url(artifact)
                if not domain:
                    raise ValueError(f"Could not extract a domain from URL: {artifact!r}")
                logger.info("WHOIS URL→domain/ip lookup: %s → %s", artifact, domain)

                if validators.domain(domain):
                    return await loop.run_in_executor(None, _whois_domain, domain)
                elif validators.ipv4(domain) or validators.ipv6(domain):
                    return await loop.run_in_executor(None, _whois_ip, domain)
                else:
                    raise ValueError(f"Extracted domain from URL is neither a valid domain nor IP: {domain!r}")
            case _:
                # Should never reach here — HASH is handled in start()
                raise ValueError(
                    f"WhoisIntegration does not support artifact type {artifact_type!r}"
                )

    # ------------------------------------------------------------------
    # Unused abstract stubs  (required by BaseIntegration ABC)
    # BaseIntegration._call_api is never reached because start() is overridden,
    # but the ABC demands implementations for both abstract methods.
    # ------------------------------------------------------------------

    def _build_request(self, artifact, artifact_type, api_key):  # type: ignore[override]
        raise NotImplementedError("WhoisIntegration does not use HTTP requests.")

    def _parse_response(self, response):  # type: ignore[override]
        raise NotImplementedError("WhoisIntegration does not use HTTP responses.")


# ---------------------------------------------------------------------------
# Standalone test  —  python -m src.integrations.engines.whois
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import asyncio, logging, sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    )

    TEST_CONFIG = {
        "name":    "whois",
        "base_url": "",        # not used
        "apis":    [],         # no API keys needed
        "timeout":  20,
        "retry_count":      0,
        "rate_limit_delay": 0,
    }

    TEST_CASES: list[tuple[str, ArtifactType]] = [
        ("google.com",           ArtifactType.DOMAIN),
        ("8.8.8.8",              ArtifactType.IP),
        ("https://github.com/",  ArtifactType.URL),
        (
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            ArtifactType.HASH,   # should be skipped gracefully
        ),
    ]

    async def _run() -> None:
        integration = WhoisIntegration(TEST_CONFIG)
        print(f"\n{'═' * 62}")
        print("  WhoisIntegration — standalone test")
        print(f"{'═' * 62}")

        for artifact, artifact_type in TEST_CASES:
            result = await integration.start(artifact, artifact_type)
            status = "✓" if result.success else "✗"

            print(f"\n  {status}  [{artifact_type.value}]  {artifact}")
            print(f"     elapsed : {result.elapsed:.2f}s")

            if not result.success:
                print(f"     error   : {result.error}")
                continue

            if result.data is None:
                print("     skipped (no WHOIS data for this type)")
                continue

            # Print a tidy subset of the most useful WHOIS fields
            SHOW_FIELDS_DOMAIN = [
                "domain_name", "registrar", "creation_date",
                "expiration_date", "name_servers", "status",
            ]
            SHOW_FIELDS_IP = [
                "asn", "asn_cidr", "asn_country_code",
                "asn_description", "network",
            ]
            fields = (
                SHOW_FIELDS_IP
                if artifact_type == ArtifactType.IP
                else SHOW_FIELDS_DOMAIN
            )
            for field in fields:
                value = result.data.get(field)
                if value is not None:
                    # Trim long values for readability
                    display = str(value)
                    if len(display) > 80:
                        display = display[:77] + "…"
                    print(f"     {field:<22}: {display}")

    asyncio.run(_run())