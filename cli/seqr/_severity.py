"""
algorithm_risk (0-10) → severity string.
"""

SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def severity_for_risk(risk: int) -> str:
    if risk >= 9:
        return "critical"
    if risk >= 7:
        return "high"
    if risk >= 4:
        return "medium"
    if risk >= 1:
        return "low"
    return "low"
