"""
ioc_enrichment/orchestrator.py
--------------------------------
EnrichmentOrchestrator — runs all enabled integrations concurrently
and collects results within their individual timeouts.
"""

from __future__ import annotations

import asyncio
from typing import Any

from src.integrations.engines.base import BaseIntegration
from src.integrations.models import ArtifactType, EnrichmentResult
from src.integrations.configurations import INTEGRATION_REGISTRY
from src.logger import create_logger

logger = create_logger(__name__)


class EnrichmentOrchestrator:
    """
    Instantiate with the INTEGRATIONS config list, then call ``enrich()``.

    Each enabled integration runs in its own asyncio Task.  Tasks that
    exceed their configured timeout are cancelled and contribute a
    ``success=False`` result — they never block other integrations.

    Parameters
    ----------
    integrations_config : list[dict]
        The INTEGRATIONS list from config.py (or any compatible list).
    """

    def __init__(self, integrations_config: list[dict[str, Any]]) -> None:
        self._integrations: dict[str, BaseIntegration] = {}
        self.allowed_types: dict[str, list[str]] = {}

        for cfg in integrations_config:
            if not cfg.get("enabled", False):
                logger.info("Skipping disabled integration: %s", cfg["name"])
                continue

            classname = cfg.get("classname", "")
            allowed_types = cfg.get("allowed_types", [])
            cls       = INTEGRATION_REGISTRY.get(classname)

            if cls is None:
                logger.error("Unknown classname %r — skipping.", classname)
                continue

            self._integrations[classname] = cls(cfg)
            self.allowed_types[classname] = allowed_types
            logger.info("Registered integration: %s", cfg["name"])

    # ------------------------------------------------------------------
    # Public entry-point
    # ------------------------------------------------------------------

    async def enrich(
        self,
        artifact:      str,
        artifact_type: ArtifactType | str,
    ) -> list[EnrichmentResult]:
        """
        Enrich a single IOC across all enabled integrations concurrently.

        Parameters
        ----------
        artifact : str
            The IOC value (IP, domain, URL, or hash).
        artifact_type : ArtifactType | str
            One of ``"ip"``, ``"domain"``, ``"url"``, ``"hash"``.

        Returns
        -------
        list[EnrichmentResult]
            One result per enabled integration, in arrival order.
            Never raises.
        """
        if not self._integrations:
            logger.warning("No enabled integrations — returning empty results.")
            return []

        if isinstance(artifact_type, str):
            artifact_type = ArtifactType(artifact_type)

        allowed_integrations = [
            self._integrations[name] for name, types in self.allowed_types.items() if artifact_type.value in types or not types
        ]
        logger.info(
            "Enriching %s:%s across %d integration(s)",
            artifact_type.value, artifact, len(allowed_integrations),
        )

        tasks = [
            asyncio.create_task(
                self._run_with_timeout(integration, artifact, artifact_type),
                name=integration.name,
            )
            for integration in allowed_integrations
        ]

        results: list[EnrichmentResult] = []
        for coro in asyncio.as_completed(tasks):
            result = await coro
            results.append(result)
            logger.info(
                "%s  %-20s  %.2fs",
                "OK" if result.success else "ERR",
                result.integration,
                result.elapsed,
            )

        return results

    # ------------------------------------------------------------------
    # Per-task timeout wrapper
    # ------------------------------------------------------------------

    @staticmethod
    async def _run_with_timeout(
        integration:   BaseIntegration,
        artifact:      str,
        artifact_type: ArtifactType,
    ) -> EnrichmentResult:
        try:
            return await asyncio.wait_for(
                integration.start(artifact, artifact_type),
                timeout=integration.timeout,
            )
        except asyncio.TimeoutError:
            logger.warning(
                "Integration %r timed out after %ss",
                integration.name, integration.timeout,
            )
            return EnrichmentResult(
                integration=integration.name,
                artifact=artifact,
                artifact_type=artifact_type,
                success=False,
                error=f"Timed out after {integration.timeout}s",
                elapsed=integration.timeout,
            )