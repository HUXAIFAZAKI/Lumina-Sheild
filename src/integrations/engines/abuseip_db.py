"""
src/integrations/engines/abuseipdb.py
--------------------------------------
AbuseIPDB integration.

AbuseIPDB API v2 endpoint mapping
-----------------------------------
  ip     → GET /api/v2/check    — abuse confidence score, ISP, usage type …
           GET /api/v2/reports  — paginated abuse report history
           Both endpoints are fetched concurrently and merged under the
           keys ``"check"`` and ``"reports"`` in the result dict.

  domain → SKIP  (AbuseIPDB is IP-only — returns success=True, data=None)

  url    → host extracted from URL:
             · if host is already an IP  → proceed as IP lookup
             · if host is a domain name  → resolve to IP then proceed
             · if resolution fails       → SKIP

  hash   → SKIP

Authentication
--------------
  Header:  Key: <api_key>
  Keys rotate on HTTP 401 / 403 / 429.

Rate limits (free tier)
-----------------------
  /check   — 1 000 requests / day
  /reports — 1 000 requests / day

Docs: https://docs.abuseipdb.com

Run standalone
--------------
    ABUSEIPDB_API_KEY=your_key python -m src.integrations.engines.abuseipdb
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
import urllib.parse
from typing import Any

import httpx

from src.integrations.engines.base import BaseIntegration
from src.integrations.models import ArtifactType, EnrichmentResult
from src.logger import create_logger

logger = create_logger()


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CHECK_MAX_AGE_DAYS: int = 90   # days of history requested from /check + /reports
_REPORTS_PER_PAGE:   int = 100  # max records per /reports page (API ceiling)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_valid_ip(value: str) -> bool:
    """Return True if *value* is a parseable IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _extract_host(url: str) -> str:
    """
    Pull the bare hostname or IP out of a URL.

    >>> _extract_host("https://1.2.3.4/path?x=1")
    '1.2.3.4'
    >>> _extract_host("https://evil.example.com:8080/")
    'evil.example.com'
    """
    parsed = urllib.parse.urlparse(url)
    host   = parsed.hostname or parsed.netloc
    return host.split(":")[0].strip().lower()


def _resolve_to_ip(host: str) -> str | None:
    """
    Blocking DNS resolution.  Returns the first resolved IPv4 string or None.
    Runs in a thread-pool executor — never called directly on the event loop.
    """
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Synthetic response wrappers
# (satisfy the raise_for_status / json contract from BaseIntegration._call_api
#  without being real httpx.Response objects)
# ---------------------------------------------------------------------------

class _MergedResponse:
    """
    Wraps the pre-merged dict produced by concurrent /check + /reports calls.
    Passed through _parse_response → returned as EnrichmentResult.data.
    """

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def raise_for_status(self) -> None:
        pass  # section-level errors are encoded inside the dict

    def json(self) -> dict[str, Any]:
        return self._data


class _SkipResponse:
    """
    Signals that this artifact type is not supported by AbuseIPDB.
    Detected in start() before the retry loop runs — results in
    EnrichmentResult(success=True, data=None).
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason

    def raise_for_status(self) -> None:
        pass

    def json(self) -> None:  # type: ignore[override]
        return None


# ---------------------------------------------------------------------------
# Integration class
# ---------------------------------------------------------------------------

class AbuseIPDBIntegration(BaseIntegration):
    """
    AbuseIPDB v2 enrichment integration.

    Supported artifact types
    ------------------------
    IP     → /check + /reports (concurrent)
    URL    → host extracted → resolved to IP if needed → same as IP
    DOMAIN → skipped gracefully
    HASH   → skipped gracefully
    """

    # ------------------------------------------------------------------
    # start()  — overrides BaseIntegration to intercept skips early
    # ------------------------------------------------------------------

    async def start(
        self,
        artifact:      str,
        artifact_type: ArtifactType | str,
    ) -> EnrichmentResult:
        """
        Entry point called by the orchestrator.

        Overrides BaseIntegration.start() so that _SkipResponse is
        detected before the retry/rotation loop fires, preventing
        unnecessary key rotations for unsupported types.
        """
        if isinstance(artifact_type, str):
            artifact_type = ArtifactType(artifact_type)

        t0 = time.monotonic()

        # --- Resolve the effective IP to look up (or decide to skip) -------
        effective_ip, skip_reason = await self._resolve_artifact(artifact, artifact_type)

        if skip_reason:
            logger.info("AbuseIPDB skip [%s] %s — %s", artifact_type.value, artifact, skip_reason)
            return EnrichmentResult(
                integration=self.name,
                artifact=artifact,
                artifact_type=artifact_type,
                success=True,
                data=None,
                error=None,
                elapsed=time.monotonic() - t0,
            )

        # --- Delegate actual IP lookup to base retry/rotation machinery -----
        # We temporarily redirect the artifact to the resolved IP so the base
        # class sends the right value to the API while the result still
        # records the original artifact for traceability.
        result = await super().start(effective_ip, artifact_type)  # type: ignore[arg-type]
        result.artifact      = artifact        # restore original value
        result.artifact_type = artifact_type
        result.elapsed       = time.monotonic() - t0
        return result

    # ------------------------------------------------------------------
    # Artifact resolution  (called before retry loop)
    # ------------------------------------------------------------------

    async def _resolve_artifact(
        self,
        artifact:      str,
        artifact_type: ArtifactType,
    ) -> tuple[str | None, str | None]:
        """
        Determine the IP address to query (if any).

        Returns
        -------
        (effective_ip, None)  — proceed with this IP
        (None, reason)        — skip; reason is a human-readable string
        """
        match artifact_type:

            case ArtifactType.IP:
                if not _is_valid_ip(artifact):
                    return None, f"{artifact!r} is not a valid IP address"
                return artifact, None

            case ArtifactType.URL:
                host = _extract_host(artifact)
                if not host:
                    return None, f"Cannot extract host from URL: {artifact!r}"
                if _is_valid_ip(host):
                    return host, None
                # Hostname — resolve in thread pool
                loop     = asyncio.get_running_loop()
                resolved = await loop.run_in_executor(None, _resolve_to_ip, host)
                if resolved:
                    logger.info("URL host %s resolved to %s", host, resolved)
                    return resolved, None
                return None, f"URL host {host!r} could not be resolved to an IP"

            case ArtifactType.DOMAIN:
                return None, "AbuseIPDB is IP-only; domain lookups are not supported"

            case ArtifactType.HASH:
                return None, "AbuseIPDB does not support hash lookups"

            case _:
                return None, f"Unsupported artifact type: {artifact_type!r}"

    # ------------------------------------------------------------------
    # _build_request  (ABC requirement — not used; _call_api is overridden)
    # ------------------------------------------------------------------

    def _build_request(
        self,
        artifact:      str,
        artifact_type: ArtifactType,
        api_key:       str,
    ) -> tuple[str, str, dict[str, Any]]:
        raise NotImplementedError(
            "AbuseIPDBIntegration uses _call_api directly; "
            "_build_request is never invoked."
        )

    # ------------------------------------------------------------------
    # _call_api override  — concurrent /check + /reports
    # ------------------------------------------------------------------

    async def _call_api(
        self,
        artifact:      str,     # always a valid IP at this point (skips handled in start)
        artifact_type: ArtifactType,
        api_key:       str,
    ) -> httpx.Response:
        headers = {
            "Key":    api_key,
            "Accept": "application/json",
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            check_task   = asyncio.create_task(
                self._fetch_check(client, artifact, headers),   name="check"
            )
            reports_task = asyncio.create_task(
                self._fetch_reports(client, artifact, headers), name="reports"
            )
            check_out, reports_out = await asyncio.gather(
                check_task, reports_task, return_exceptions=True
            )

        # Surface auth / rate-limit errors from /check so base class can rotate keys
        if isinstance(check_out, httpx.HTTPStatusError):
            raise check_out

        merged: dict[str, Any] = {}

        if isinstance(check_out, Exception):
            merged["check"]   = {"error": str(check_out)}
        else:
            merged["check"]   = check_out

        if isinstance(reports_out, Exception):
            merged["reports"] = {"error": str(reports_out)}
        else:
            merged["reports"] = reports_out

        return _MergedResponse(merged)

    # ------------------------------------------------------------------
    # Section fetchers
    # ------------------------------------------------------------------

    async def _fetch_check(
        self,
        client:  httpx.AsyncClient,
        ip:      str,
        headers: dict[str, str],
    ) -> dict[str, Any]:
        """
        GET /api/v2/check
        Returns abuse confidence score, ISP, usage type, country, domain,
        total reports, last reported date, and recent reporter info.
        """
        resp = await client.get(
            f"{self.base_url}/api/v2/check",
            headers=headers,
            params={
                "ipAddress":    ip,
                "maxAgeInDays": _CHECK_MAX_AGE_DAYS,
                "verbose":      True,    # includes lastReporter country + categories
            },
        )
        resp.raise_for_status()
        # AbuseIPDB wraps its payload in a "data" key
        payload = resp.json()
        return payload.get("data", payload)

    async def _fetch_reports(
        self,
        client:  httpx.AsyncClient,
        ip:      str,
        headers: dict[str, str],
    ) -> dict[str, Any]:
        """
        GET /api/v2/reports
        Returns paginated list of individual abuse reports with categories,
        comment excerpts, and reporter metadata.
        """
        resp = await client.get(
            f"{self.base_url}/api/v2/reports",
            headers=headers,
            params={
                "ipAddress":    ip,
                "maxAgeInDays": _CHECK_MAX_AGE_DAYS,
                "perPage":      _REPORTS_PER_PAGE,
                "page":         1,
            },
        )
        resp.raise_for_status()
        payload = resp.json()
        return {
            "total_count": payload.get("meta", {}).get("totalCount", 0),
            "page":        1,
            "per_page":    _REPORTS_PER_PAGE,
            "reports":     payload.get("data", []),
        }

    # ------------------------------------------------------------------
    # _parse_response
    # ------------------------------------------------------------------

    def _parse_response(self, response: httpx.Response) -> dict[str, Any] | None:
        return response.json()


# ---------------------------------------------------------------------------
# Standalone test  —  ABUSEIPDB_API_KEY=your_key python -m src.integrations.engines.abuseipdb
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import asyncio, logging, os

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    )

    API_KEY = os.getenv("ABUSEIPDB_API_KEY", "PLACEHOLDER_KEY")

    TEST_CONFIG = {
        "name":             "abuseipdb",
        "base_url":         "https://api.abuseipdb.com",
        "apis":             [API_KEY],
        "timeout":          20,
        "retry_count":      1,
        "rate_limit_delay": 1,
    }

    TEST_CASES: list[tuple[str, ArtifactType]] = [
        ("8.8.8.8",                    ArtifactType.IP),       # known clean IP
        ("185.220.101.1",              ArtifactType.IP),       # known Tor exit node
        ("https://8.8.8.8/dns-query",  ArtifactType.URL),      # IP-in-URL
        ("https://example.com/page",   ArtifactType.URL),      # domain-in-URL → resolve
        ("google.com",                 ArtifactType.DOMAIN),   # skip
        ("d41d8cd98f00b204e9800998ecf8427e",
                                       ArtifactType.HASH),     # skip
    ]

    # Fields to preview from each section
    _CHECK_FIELDS   = ["ipAddress", "abuseConfidenceScore", "countryCode",
                       "usageType", "isp", "totalReports", "lastReportedAt"]
    _REPORTS_FIELDS = ["total_count", "per_page"]

    async def _run() -> None:
        integration = AbuseIPDBIntegration(TEST_CONFIG)
        print(f"\n{'═' * 64}")
        print("  AbuseIPDBIntegration — standalone test")
        print(f"{'═' * 64}")

        for artifact, artifact_type in TEST_CASES:
            result = await integration.start(artifact, artifact_type)
            status = "✓" if result.success else "✗"
            label  = artifact if len(artifact) <= 44 else artifact[:41] + "…"

            print(f"\n  {status}  [{artifact_type.value:<6}]  {label}")
            print(f"     elapsed : {result.elapsed:.2f}s")

            if not result.success:
                print(f"     error   : {result.error}")
                continue

            if result.data is None:
                print("     skipped — not supported by AbuseIPDB")
                continue

            check   = result.data.get("check", {})
            reports = result.data.get("reports", {})

            print("     [check]")
            for f in _CHECK_FIELDS:
                val = check.get(f)
                if val is not None:
                    print(f"       {f:<28}: {val}")

            print("     [reports]")
            for f in _REPORTS_FIELDS:
                val = reports.get(f)
                if val is not None:
                    print(f"       {f:<28}: {val}")

            sample = reports.get("reports", [])[:2]
            for i, rep in enumerate(sample, 1):
                cats = rep.get("categories", [])
                print(f"       report #{i:<3} categories: {cats}")

    asyncio.run(_run())