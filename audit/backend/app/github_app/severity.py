"""algorithm_risk (0-10) → severity — mirrors the CLI's ``seqr._severity``.

The hosted App must grade findings the same way ``seqr ci`` does, so a commit status and a
CLI gate never disagree on the same PR. Kept as a tiny standalone copy because the backend
does not depend on the CLI package.
"""
from __future__ import annotations

SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def severity_for_risk(risk: int) -> str:
    if risk >= 9:
        return "critical"
    if risk >= 7:
        return "high"
    if risk >= 4:
        return "medium"
    return "low"


def at_or_above(severity: str, threshold: str) -> bool:
    """True if ``severity`` is at least as severe as ``threshold``.

    Unknown names are treated as the lowest rank so a typo can never silently arm the gate.
    """
    try:
        return SEVERITY_ORDER.index(severity) >= SEVERITY_ORDER.index(threshold)
    except ValueError:
        return False
