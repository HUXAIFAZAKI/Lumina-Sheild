"""
src/integrations/engines/alienvault_otx.py
-------------------------------------------
AlienVault OTX (Open Threat Exchange) integration.

OTX API v1 endpoint mapping
----------------------------
  ip     → GET /api/v1/indicators/IPv4/{ip}/general
              GET /api/v1/indicators/IPv4/{ip}/reputation
              GET /api/v1/indicators/IPv4/{ip}/geo
              GET /api/v1/indicators/IPv4/{ip}/malware

  domain → GET /api/v1/indicators/domain/{domain}/general
              GET /api/v1/indicators/domain/{domain}/whois
              GET /api/v1/indicators/domain/{domain}/malware
              GET /api/v1/indicators/domain/{domain}/url_list

  url    → GET /api/v1/indicators/url/{encoded_url}/general

  hash   → GET /api/v1/indicators/file/{hash}/general
              GET /api/v1/indicators/file/{hash}/analysis

For IP and domain lookups, multiple OTX "sections" are fetched
concurrently and merged into a single response dict so the caller
receives the full picture in one result.

Authentication
--------------
  OTX uses a single header:  X-OTX-API-KEY: <key>
  Keys rotate on HTTP 400 / 401 / 403 / 429.

Docs: https://otx.alienvault.com/api

Run standalone
--------------
    OTX_API_KEY=your_key python -m src.integrations.engines.alienvault_otx
"""

from __future__ import annotations

import asyncio
import urllib.parse
from typing import Any

import httpx

from src.integrations.engines.base import BaseIntegration
from src.integrations.models import ArtifactType
from src.logger import create_logger

logger = create_logger()


# ---------------------------------------------------------------------------
# Per-type section maps
# Each section becomes a top-level key in the merged response dict.
# ---------------------------------------------------------------------------

_IP_SECTIONS: list[str] = [
    "general",
    "reputation",
    "geo",
    "malware",
]

_DOMAIN_SECTIONS: list[str] = [
    "general",
    "whois",
    "malware",
    "url_list",
]

_FILE_SECTIONS: list[str] = [
    "general",
    "analysis",
]


# ---------------------------------------------------------------------------
# Integration
# ---------------------------------------------------------------------------

class AlienVaultOTXIntegration(BaseIntegration):
    """
    AlienVault OTX v1 enrichment integration.

    Supports: IP, DOMAIN, URL, HASH.

    Multi-section types (IP, DOMAIN, HASH) fire all section requests
    concurrently within a single ``_call_api`` call and return the merged
    result.  This keeps the base retry/rotation contract intact while
    avoiding unnecessary sequential round-trips.
    """

    # ------------------------------------------------------------------
    # _build_request — required by ABC; used only for single-section
    # types (URL).  Multi-section types bypass it via _call_api override.
    # ------------------------------------------------------------------

    def _build_request(
        self,
        artifact:      str,
        artifact_type: ArtifactType,
        api_key:       str,
    ) -> tuple[str, str, dict[str, Any]]:
        """
        Build the request tuple for single-endpoint types.

        Multi-section types (IP, DOMAIN, HASH) are handled in
        ``_call_api`` and never reach this method.
        """
        headers = {
            "X-OTX-API-KEY": api_key,
            "Accept":        "application/json",
        }

        match artifact_type:
            case ArtifactType.URL:
                # OTX expects the URL to be percent-encoded in the path
                encoded = urllib.parse.quote(artifact, safe="")
                return (
                    "GET",
                    f"{self.base_url}/api/v1/indicators/url/{encoded}/general",
                    {"headers": headers},
                )

            case _:
                # Should never be reached — all other types override _call_api
                raise NotImplementedError(
                    f"_build_request called unexpectedly for type {artifact_type!r}. "
                    "Multi-section types are handled in _call_api."
                )

    # ------------------------------------------------------------------
    # _call_api override — concurrent multi-section fetch
    # ------------------------------------------------------------------

    async def _call_api(
        self,
        artifact:      str,
        artifact_type: ArtifactType,
        api_key:       str,
    ) -> httpx.Response:
        """
        Override to handle multi-section OTX lookups concurrently.

        URL lookups are single-section and use the default base path.
        IP, DOMAIN, and HASH lookups fire all sections in parallel and
        return a synthetic ``_MultiSectionResponse`` wrapper so the base
        class machinery (raise_for_status → _parse_response) still works.
        """
        if artifact_type == ArtifactType.URL:
            return await super()._call_api(artifact, artifact_type, api_key)

        headers = {
            "X-OTX-API-KEY": api_key,
            "Accept":        "application/json",
        }

        indicator_type, sections = self._indicator_meta(artifact_type)
        base_path = f"{self.base_url}/api/v1/indicators/{indicator_type}/{artifact}"

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            tasks = [
                asyncio.create_task(
                    self._fetch_section(client, f"{base_path}/{section}", headers),
                    name=section,
                )
                for section in sections
            ]
            responses = await asyncio.gather(*tasks, return_exceptions=True)

        # Build merged dict; propagate the first real HTTP error if all fail
        merged: dict[str, Any] = {}
        first_http_error: httpx.HTTPStatusError | None = None

        for section, outcome in zip(sections, responses):
            if isinstance(outcome, httpx.HTTPStatusError):
                first_http_error = outcome
                merged[section] = {"error": str(outcome)}
            elif isinstance(outcome, Exception):
                merged[section] = {"error": str(outcome)}
            else:
                merged[section] = outcome   # already a dict from _fetch_section

        # If every section failed with an auth/rate error, surface it so the
        # base class rotation machinery can act on the status code.
        all_failed = all(isinstance(r, Exception) for r in responses)
        if all_failed and first_http_error is not None:
            raise first_http_error

        return _MultiSectionResponse(merged)

    # ------------------------------------------------------------------
    # Response parser
    # ------------------------------------------------------------------

    def _parse_response(self, response: httpx.Response) -> dict[str, Any]:
        """
        Return the JSON payload.

        For multi-section lookups ``response`` is a ``_MultiSectionResponse``
        whose ``.json()`` returns the pre-merged dict.
        For URL lookups it is a real ``httpx.Response``.
        """
        return response.json()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _indicator_meta(artifact_type: ArtifactType) -> tuple[str, list[str]]:
        """
        Return the OTX indicator path segment and list of sections for
        a given artifact type.
        """
        match artifact_type:
            case ArtifactType.IP:
                return "IPv4", _IP_SECTIONS
            case ArtifactType.DOMAIN:
                return "domain", _DOMAIN_SECTIONS
            case ArtifactType.HASH:
                return "file", _FILE_SECTIONS
            case _:
                raise ValueError(
                    f"AlienVaultOTXIntegration: no indicator meta for {artifact_type!r}"
                )

    @staticmethod
    async def _fetch_section(
        client:  httpx.AsyncClient,
        url:     str,
        headers: dict[str, str],
    ) -> dict[str, Any]:
        """Fetch one OTX section URL and return its parsed JSON."""
        response = await client.get(url, headers=headers)
        response.raise_for_status()
        return response.json()


# ---------------------------------------------------------------------------
# Synthetic response wrapper for multi-section results
# ---------------------------------------------------------------------------

class _MultiSectionResponse:
    """
    Thin wrapper that satisfies the ``httpx.Response`` interface expected
    by ``BaseIntegration._call_api`` (specifically ``raise_for_status`` and
    ``json()``) without being a real HTTP response.

    This lets the base class machinery remain unmodified while multi-section
    lookups return a pre-merged payload.
    """

    def __init__(self, merged: dict[str, Any]) -> None:
        self._merged = merged

    def raise_for_status(self) -> None:
        """No-op — errors were surfaced individually per section."""

    def json(self) -> dict[str, Any]:
        return self._merged


# ---------------------------------------------------------------------------
# Standalone test  —  OTX_API_KEY=your_key python -m src.integrations.engines.alienvault_otx
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import asyncio, logging, os, sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    )

    API_KEY = os.getenv("OTX_API_KEY", "PLACEHOLDER_KEY")

    TEST_CONFIG = {
        "name":             "alienvault_otx",
        "base_url":         "https://otx.alienvault.com",
        "apis":             [API_KEY],
        "timeout":          20,
        "retry_count":      1,
        "rate_limit_delay": 1,
    }

    TEST_CASES: list[tuple[str, ArtifactType]] = [
        ("8.8.8.8",                                       ArtifactType.IP),
        ("google.com",                                    ArtifactType.DOMAIN),
        ("https://google.com",                            ArtifactType.URL),
        ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                                                          ArtifactType.HASH),
    ]

    # Top-level keys to preview per section for each type
    _PREVIEW_KEYS = {
        ArtifactType.IP:     {"general": ["pulse_info", "reputation"],
                              "geo":     ["country_name", "city"],
                              "malware": ["count"]},
        ArtifactType.DOMAIN: {"general": ["pulse_info"],
                              "whois":   ["registrar", "emails"],
                              "malware": ["count"]},
        ArtifactType.URL:    {"":        ["url", "domain", "result"]},
        ArtifactType.HASH:   {"general": ["pulse_info", "type_title"],
                              "analysis":["info"]},
    }

    async def _run() -> None:
        integration = AlienVaultOTXIntegration(TEST_CONFIG)
        print(f"\n{'═' * 64}")
        print("  AlienVaultOTXIntegration — standalone test")
        print(f"{'═' * 64}")

        for artifact, artifact_type in TEST_CASES:
            result = await integration.start(artifact, artifact_type)
            status = "✓" if result.success else "✗"
            label  = artifact if len(artifact) <= 40 else artifact[:37] + "…"

            print(f"\n  {status}  [{artifact_type.value}]  {label}")
            print(f"     elapsed : {result.elapsed:.2f}s")

            if not result.success:
                print(f"     error   : {result.error}")
                continue

            # Pretty-print a short preview per section
            preview_map = _PREVIEW_KEYS.get(artifact_type, {})
            data = result.data or {}

            if artifact_type == ArtifactType.URL:
                # URL result is flat, not section-keyed
                for key in list(data.keys())[:6]:
                    val = str(data[key])[:80]
                    print(f"     {key:<24}: {val}")
            else:
                for section, keys in preview_map.items():
                    section_data = data.get(section, {})
                    if not section_data:
                        continue
                    print(f"     [{section}]")
                    for key in keys:
                        val = section_data.get(key)
                        if val is not None:
                            print(f"       {key:<22}: {str(val)[:72]}")

    asyncio.run(_run())