"""
ioc_enrichment/base_integration.py
------------------------------------
Abstract base class for all IOC enrichment integrations.

Concrete integrations only need to implement two methods:
  _build_request(artifact, artifact_type, api_key) → (method, url, kwargs)
  _parse_response(response)                         → dict

Everything else — retry loop, key rotation, timeout handling, structured
error results — is handled here once and inherited automatically.
"""

from __future__ import annotations

import asyncio
from src.logger import create_logger
import time
from abc import ABC, abstractmethod
from typing import Any

import httpx

from src.integrations.models import ArtifactType, EnrichmentResult, ROTATE_ON
from src.integrations.rotator import ApiKeyRotator


class BaseIntegration(ABC):
    """
    Abstract base class for all IOC enrichment integrations.

    Parameters
    ----------
    config : dict
        A single entry from the INTEGRATIONS config list.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self.name:             str   = config["name"]
        self.base_url:         str   = config["base_url"].rstrip("/")
        self.api_keys:         list  = config.get("apis", [])
        self.timeout:          float = float(config.get("timeout", 20))
        self.retry_count:      int   = config.get("retry_count", 2)
        self.rate_limit_delay: float = float(config.get("rate_limit_delay", 1))
        self._log = create_logger(f"integration.{self.name}")

    # ------------------------------------------------------------------
    # Public entry-point  (called by EnrichmentOrchestrator)
    # ------------------------------------------------------------------

    async def start(
        self,
        artifact:      str,
        artifact_type: ArtifactType | str,
    ) -> EnrichmentResult:
        """
        Run the enrichment lookup with retry + key-rotation logic.

        Always returns an ``EnrichmentResult`` — never raises.
        """
        if isinstance(artifact_type, str):
            artifact_type = ArtifactType(artifact_type)

        t0 = time.monotonic()
        try:
            result = await self._execute_with_rotation(artifact, artifact_type)
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

    # ------------------------------------------------------------------
    # Retry + rotation core
    # ------------------------------------------------------------------

    async def _execute_with_rotation(
        self,
        artifact:      str,
        artifact_type: ArtifactType,
    ) -> EnrichmentResult:
        rotator = ApiKeyRotator(self.api_keys)
        attempt = 0

        while attempt <= self.retry_count:
            attempt += 1
            api_key = rotator.current_key

            self._log.info(
                "Attempt %d/%d  key=…%s  %s:%s",
                attempt, self.retry_count + 1,
                api_key[-4:], artifact_type.value, artifact,
            )

            try:
                response = await self._call_api(artifact, artifact_type, api_key)
                data     = self._parse_response(response)

                return EnrichmentResult(
                    integration=self.name,
                    artifact=artifact,
                    artifact_type=artifact_type,
                    success=True,
                    data=data,
                    api_key_used=EnrichmentResult.mask_key(api_key),
                )

            except httpx.HTTPStatusError as exc:
                status = exc.response.status_code
                self._log.warning("HTTP %d on attempt %d", status, attempt)

                if status in ROTATE_ON:
                    try:
                        rotator.rotate()
                    except ApiKeyRotator.KeysExhaustedError as kee:
                        return EnrichmentResult(
                            integration=self.name,
                            artifact=artifact,
                            artifact_type=artifact_type,
                            success=False,
                            error=str(kee),
                        )
                else:
                    # Non-rotatable error — no point trying another key
                    return EnrichmentResult(
                        integration=self.name,
                        artifact=artifact,
                        artifact_type=artifact_type,
                        success=False,
                        error=f"HTTP {status}: {exc.response.text[:200]}",
                    )

            except httpx.RequestError as exc:
                self._log.warning("Network error on attempt %d: %s", attempt, exc)
                if attempt > self.retry_count:
                    return EnrichmentResult(
                        integration=self.name,
                        artifact=artifact,
                        artifact_type=artifact_type,
                        success=False,
                        error=f"Network error after {attempt} attempt(s): {exc}",
                    )

            # Pause before the next retry
            if attempt <= self.retry_count:
                await asyncio.sleep(self.rate_limit_delay)

        return EnrichmentResult(
            integration=self.name,
            artifact=artifact,
            artifact_type=artifact_type,
            success=False,
            error="Retry limit reached without a conclusive response.",
        )

    # ------------------------------------------------------------------
    # HTTP transport  (one client per call — stateless, safe to override)
    # ------------------------------------------------------------------

    async def _call_api(
        self,
        artifact:      str,
        artifact_type: ArtifactType,
        api_key:       str,
    ) -> httpx.Response:
        method, url, kwargs = self._build_request(artifact, artifact_type, api_key)
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.request(method, url, **kwargs)
        response.raise_for_status()
        return response

    # ------------------------------------------------------------------
    # Abstract interface — subclasses implement these two methods only
    # ------------------------------------------------------------------

    @abstractmethod
    def _build_request(
        self,
        artifact:      str,
        artifact_type: ArtifactType,
        api_key:       str,
    ) -> tuple[str, str, dict[str, Any]]:
        """
        Build the HTTP request parameters.

        Returns
        -------
        tuple[method, url, kwargs]
            method  — HTTP verb ("GET", "POST", …)
            url     — fully-qualified endpoint URL
            kwargs  — forwarded to httpx.AsyncClient.request
                      (e.g. headers, data, params, json)
        """

    @abstractmethod
    def _parse_response(self, response: httpx.Response) -> dict[str, Any]:
        """
        Extract the relevant payload from the raw HTTP response.

        Return ``response.json()`` directly if no trimming is needed.
        """