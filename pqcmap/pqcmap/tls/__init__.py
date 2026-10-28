"""Best-effort PQC-hybrid TLS: a client context builder + an honest capability report.

    from pqcmap import tls
    ctx, caps = tls.build_client_context()
    print(caps.summary())          # what this runtime can actually do

See :mod:`pqcmap.tls.context` for the detailed capability model and the MTU caveat, and
:mod:`pqcmap.tls.http` for ready-made httpx / requests clients that use this context.
"""
from pqcmap.tls.context import (
    PQC_HYBRID_GROUP,
    TLSCapabilities,
    build_client_context,
    capabilities,
    report,
)

__all__ = [
    "PQC_HYBRID_GROUP",
    "TLSCapabilities",
    "build_client_context",
    "capabilities",
    "report",
]
