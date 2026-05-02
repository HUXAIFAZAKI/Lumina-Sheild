
from __future__ import annotations
import sys
import os
# Add project root (parent of src) to Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.insert(0, project_root)

# Now this will work
from configurations import INTEGRATIONS

import asyncio

from configurations import INTEGRATIONS
from models import ArtifactType, EnrichmentResult
from orchestrator import EnrichmentOrchestrator



# ---------------------------------------------------------------------------
# Pretty-print helper
# ---------------------------------------------------------------------------

def _print_results(artifact: str, artifact_type: ArtifactType, results: list[EnrichmentResult]) -> None:
    print(f"\n{'═' * 62}")
    print(f"  IOC    : {artifact}")
    print(f"  Type   : {artifact_type.value}")
    print(f"{'═' * 62}")

    if not results:
        print("  (no enabled integrations)")
        return

    for r in results:
        status = "✓" if r.success else "✗"
        print(f"\n  [{r.integration.upper()}]  {status}")
        if r.success:
            # preview = str(r.data)[:300]
            preview = str(r.data)
            ellipsis = "…" if len(str(r.data)) > 300 else ""
            print(f"  data     : {preview}{ellipsis}")
            print(f"  key used : {r.api_key_used}")
        else:
            print(f"  error    : {r.error}")
        print(f"  elapsed  : {r.elapsed:.2f}s")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main() -> None:

    orchestrator = EnrichmentOrchestrator(INTEGRATIONS)

    samples: list[tuple[str, ArtifactType]] = [
        ("http://60.3.55.113:59507/bin.sh", ArtifactType.URL),
        # ("8.8.8.8",                  ArtifactType.IP),
        # ("bhomes.com",          ArtifactType.DOMAIN),
        # ("http://malware.io/payload", ArtifactType.URL),
        # (
        #     "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        #     ArtifactType.HASH,
        # ),
    ]

    for artifact, artifact_type in samples:
        results = await orchestrator.enrich(artifact, artifact_type)
        _print_results(artifact, artifact_type, results)

    print(f"\n{'═' * 62}")
    print("  Enrichment complete.")
    print(f"{'═' * 62}\n")


if __name__ == "__main__":
    asyncio.run(main())