"""Structured discovery sources + precedence (PRD 13, forks D + #7).

A crypto observation's `source` is one of these fixed values, not a free-form string. This
lets us (a) apply deterministic precedence when projecting current state, and (b) refine to
attribute-aware precedence later (control-plane config vs actually-negotiated) without a
schema change, because the raw source is always stored.

Precedence rule (higher wins; inside beats outside):
    manual_import / manual_override   50   an operator asserted it
    discovery_agent                   40   ran inside the customer perimeter
    cloudflare_api / aws_api / azure_api  30   authoritative for *configured* posture
    active_probe                      20   authoritative for *actually negotiated* posture
    external_scanner                  10   outside-in, edge-only

Note: active_probe vs the *_api tiers is genuinely not linear across every attribute
(configured != live). v1 uses this linear order; keep the raw source to revisit later.
"""

from enum import Enum


class DiscoverySource(str, Enum):
    MANUAL_IMPORT = "manual_import"
    MANUAL_OVERRIDE = "manual_override"
    DISCOVERY_AGENT = "discovery_agent"
    CLOUDFLARE_API = "cloudflare_api"
    AWS_API = "aws_api"
    AZURE_API = "azure_api"
    ACTIVE_PROBE = "active_probe"
    EXTERNAL_SCANNER = "external_scanner"


SOURCE_PRECEDENCE: dict[str, int] = {
    DiscoverySource.MANUAL_OVERRIDE: 50,
    DiscoverySource.MANUAL_IMPORT: 50,
    DiscoverySource.DISCOVERY_AGENT: 40,
    DiscoverySource.CLOUDFLARE_API: 30,
    DiscoverySource.AWS_API: 30,
    DiscoverySource.AZURE_API: 30,
    DiscoverySource.ACTIVE_PROBE: 20,
    DiscoverySource.EXTERNAL_SCANNER: 10,
}


def precedence_for(source: str) -> int:
    """Precedence weight for a source string; unknown sources sort lowest."""
    return SOURCE_PRECEDENCE.get(source, 0)
