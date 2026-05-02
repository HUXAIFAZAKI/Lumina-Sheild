"""
ioc_enrichment/integrations/virustotal.py
------------------------------------------
VirusTotal v3 integration.

Endpoint mapping
----------------
  ip     → GET  /ip_addresses/{ip}
  domain → GET  /domains/{domain}
  url    → POST /urls  (submit)  +  GET /urls/{url_id}  (fetch report)
  hash   → GET  /files/{hash}

Run this file directly to test against the live API:
  python -m ioc_enrichment.integrations.virustotal
"""

from __future__ import annotations

import asyncio
import base64
from src.logger import create_logger
from typing import Any

import httpx

from src.integrations.engines.base import BaseIntegration
from src.integrations.models import ArtifactType
from src.logger import create_logger

logger = create_logger()


class VirusTotalIntegration(BaseIntegration):
    """VirusTotal v3 enrichment integration."""

    # ------------------------------------------------------------------
    # Request builder
    # ------------------------------------------------------------------

    def _build_request(
        self,
        artifact:      str,
        artifact_type: ArtifactType,
        api_key:       str,
    ) -> tuple[str, str, dict[str, Any]]:
        headers = {"x-apikey": api_key, "Accept": "application/json"}

        match artifact_type:
            case ArtifactType.IP:
                return "GET", f"{self.base_url}/ip_addresses/{artifact}", {"headers": headers}

            case ArtifactType.DOMAIN:
                return "GET", f"{self.base_url}/domains/{artifact}", {"headers": headers}

            case ArtifactType.HASH:
                return "GET", f"{self.base_url}/files/{artifact}", {"headers": headers}

            case ArtifactType.URL:
                # Submission step only — see _call_api override for the full flow
                return (
                    "POST",
                    f"{self.base_url}/urls",
                    {
                        "headers": {**headers, "Content-Type": "application/x-www-form-urlencoded"},
                        "data":    {"url": artifact},
                    },
                )

            case _:
                raise ValueError(
                    f"VirusTotalIntegration does not support artifact type {artifact_type!r}"
                )

    # ------------------------------------------------------------------
    # Custom _call_api for the URL two-step flow
    # ------------------------------------------------------------------

    async def _call_api(
        self,
        artifact:      str,
        artifact_type: ArtifactType,
        api_key:       str,
    ) -> httpx.Response:
        """
        Override only for URLs (POST submit → GET report).
        All other types use the default single-request path from BaseIntegration.
        """
        if artifact_type != ArtifactType.URL:
            return await super()._call_api(artifact, artifact_type, api_key)

        headers = {"x-apikey": api_key, "Accept": "application/json"}

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            # Step 1: submit the URL for analysis
            submit_resp = await client.post(
                f"{self.base_url}/urls",
                headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
                data={"url": artifact},
            )
            submit_resp.raise_for_status()

            # Step 2: fetch the analysis report using the base64-encoded URL ID
            url_id      = base64.urlsafe_b64encode(artifact.encode()).rstrip(b"=").decode()
            report_resp = await client.get(
                f"{self.base_url}/urls/{url_id}",
                headers=headers,
            )
            report_resp.raise_for_status()

        return report_resp

    # ------------------------------------------------------------------
    # Response parser
    # ------------------------------------------------------------------

    def _parse_response(self, response: httpx.Response) -> dict[str, Any]:
        return response.json()