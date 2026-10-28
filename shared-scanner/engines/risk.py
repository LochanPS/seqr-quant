"""
Risk scoring engine for SeQr.

Formulas from PRD:
  final_risk_score = min(10.0, (algorithm_risk * data_sensitivity_score * shelf_life_multiplier) / 10)
  org_risk_score   = weighted average of top-20 components (HNDL = 2× weight), scaled 0-100
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DATA_SENSITIVITY_SCORES: dict[str, int] = {
    "highly_confidential": 10,
    "confidential": 8,
    "internal": 5,
    "public": 1,
}

# Shelf-life multipliers: how long encrypted data must remain confidential
# affects severity of a harvest-now-decrypt-later attack.
DATA_SHELF_LIFE_MULTIPLIERS: dict[str, float] = {
    "ephemeral": 0.2,   # OTPs, session tokens (< 1 hour)
    "short": 0.5,       # API tokens (hours to days)
    "medium": 1.0,      # TLS session keys (days to months)
    "long": 1.5,        # Database encryption keys (months to years)
    "permanent": 2.0,   # Root CAs, long-term signing keys
}

_HNDL_LOCATION_TYPES: frozenset[str] = frozenset({
    "tls_cert", "kms_key", "jwt", "ssh_key",
})

_HNDL_SENSITIVE_LEVELS: frozenset[str] = frozenset({
    "confidential", "highly_confidential",
})

# HNDL only relevant when data persists long enough for a future quantum computer to decrypt
_HNDL_SHELF_LIFE_LEVELS: frozenset[str] = frozenset({
    "medium", "long", "permanent",
})


# ---------------------------------------------------------------------------
# Output types
# ---------------------------------------------------------------------------

@dataclass
class ComponentRiskScore:
    component_id: str
    algorithm: str
    algorithm_family: str
    algorithm_risk: int            # 0-10 from classifier
    data_sensitivity: str
    data_sensitivity_score: int    # 0-10
    final_risk_score: float        # min(10, algorithm_risk * data_sensitivity_score * shelf_life_multiplier / 10)
    hndl_risk: bool
    location_type: str
    is_public_facing: bool

    # Compliance flags
    nist_compliant: bool           # NIST SP 800-131A
    pci_compliant: bool            # PCI DSS 12.3.3
    dst_compliant: bool            # India DST Task Force 2026
    cnsa_compliant: bool           # NSA CNSA 2.0

    migration_priority: str        # critical | high | medium | low
    quantum_status: str

    # Shelf-life dimension (added v1.1)
    data_shelf_life: str = "medium"
    recommended_next_step: str = ""


@dataclass
class OrgRiskScore:
    score: int                             # 0-100
    total_components: int
    vulnerable_count: int
    hndl_critical_count: int
    critical_priority_count: int
    high_priority_count: int
    top_risk_components: list[str]         # component_ids sorted by risk


@dataclass
class ComplianceResult:
    framework: str                 # nist_800_131a | pci_dss_12_3_3 | dst_2026 | cnsa_2
    status: str                    # compliant | non_compliant | partial
    failing_components: list[str]  # component_ids causing failure
    reason: str


# ---------------------------------------------------------------------------
# Component scoring
# ---------------------------------------------------------------------------

def score_component(
    *,
    component_id: str,
    algorithm: str,
    algorithm_family: str,
    algorithm_risk: int,
    quantum_status: str,
    data_sensitivity: str = "internal",
    location_type: str = "code",
    is_public_facing: bool = True,
    key_size: Optional[int] = None,
    data_shelf_life: str = "medium",
) -> ComponentRiskScore:
    """
    Compute all risk and compliance scores for a single crypto component.

    Args:
        component_id:     Unique identifier (UUID or generated string).
        algorithm:        Canonical algorithm name (e.g. "RSA-2048", "ECDSA-P256").
        algorithm_family: Family string (RSA, ECC, DH, AES, SHA, TLS, ML-KEM, …).
        algorithm_risk:   0-10 from classifier.py.
        quantum_status:   vulnerable | safe | deprecated | unknown
        data_sensitivity: public | internal | confidential | highly_confidential
        location_type:    tls_cert | code | kms_key | ssh_key | config | jwt
        is_public_facing: True if asset is reachable from internet.
        key_size:         Optional key size in bits (used for NIST compliance).
        data_shelf_life:  ephemeral | short | medium | long | permanent
    """
    data_shelf_life = data_shelf_life or "medium"
    ds_score = DATA_SENSITIVITY_SCORES.get(data_sensitivity, 5)
    shelf_multiplier = DATA_SHELF_LIFE_MULTIPLIERS.get(data_shelf_life, 1.0)
    final_risk = round(min(10.0, (algorithm_risk * ds_score * shelf_multiplier) / 10), 2)

    hndl = (
        quantum_status == "vulnerable"
        and location_type in _HNDL_LOCATION_TYPES
        and data_sensitivity in _HNDL_SENSITIVE_LEVELS
        and is_public_facing
        and data_shelf_life in _HNDL_SHELF_LIFE_LEVELS
    )

    nist = _check_nist_800_131a(algorithm, algorithm_family, algorithm_risk, key_size)
    pci = _check_pci_dss(algorithm_family, quantum_status)
    dst = _check_dst_2026(quantum_status)
    cnsa = _check_cnsa_2(algorithm_family, quantum_status)

    priority = _migration_priority(final_risk, hndl)
    next_step = _recommended_next_step(quantum_status, hndl, priority)

    return ComponentRiskScore(
        component_id=component_id,
        algorithm=algorithm,
        algorithm_family=algorithm_family,
        algorithm_risk=algorithm_risk,
        data_sensitivity=data_sensitivity,
        data_sensitivity_score=ds_score,
        final_risk_score=final_risk,
        hndl_risk=hndl,
        location_type=location_type,
        is_public_facing=is_public_facing,
        nist_compliant=nist,
        pci_compliant=pci,
        dst_compliant=dst,
        cnsa_compliant=cnsa,
        migration_priority=priority,
        quantum_status=quantum_status,
        data_shelf_life=data_shelf_life,
        recommended_next_step=next_step,
    )


# ---------------------------------------------------------------------------
# Org-level scoring
# ---------------------------------------------------------------------------

def score_org(components: list[ComponentRiskScore]) -> OrgRiskScore:
    """
    Compute org-level quantum risk score (0-100) from a list of scored components.

    Algorithm:
    1. Take up to 20 highest-risk components (by final_risk_score).
    2. HNDL-critical components carry 2× weight.
    3. Weighted average → scaled to 0-100.
    """
    if not components:
        return OrgRiskScore(
            score=0,
            total_components=0,
            vulnerable_count=0,
            hndl_critical_count=0,
            critical_priority_count=0,
            high_priority_count=0,
            top_risk_components=[],
        )

    vulnerable = [c for c in components if c.quantum_status in ("vulnerable", "deprecated")]
    hndl_critical = [c for c in components if c.hndl_risk]
    critical_prio = [c for c in components if c.migration_priority == "critical"]
    high_prio = [c for c in components if c.migration_priority == "high"]

    # Top-20 by final_risk_score
    top_20 = sorted(components, key=lambda c: c.final_risk_score, reverse=True)[:20]

    weighted_sum = 0.0
    weight_total = 0.0
    for comp in top_20:
        weight = 2.0 if comp.hndl_risk else 1.0
        weighted_sum += comp.final_risk_score * weight
        weight_total += weight

    if weight_total > 0:
        avg_risk = weighted_sum / weight_total  # 0-10 scale
        # Scale to 0-100; max possible avg_risk is 10
        raw_score = int(round(avg_risk * 10))
    else:
        raw_score = 0

    raw_score = min(100, max(0, raw_score))

    return OrgRiskScore(
        score=raw_score,
        total_components=len(components),
        vulnerable_count=len(vulnerable),
        hndl_critical_count=len(hndl_critical),
        critical_priority_count=len(critical_prio),
        high_priority_count=len(high_prio),
        top_risk_components=[c.component_id for c in top_20],
    )


# ---------------------------------------------------------------------------
# Compliance checks
# ---------------------------------------------------------------------------

def check_compliance(
    components: list[ComponentRiskScore],
    framework: str,
) -> ComplianceResult:
    """
    Check all components against a compliance framework.

    framework: nist_800_131a | pci_dss_12_3_3 | dst_2026 | cnsa_2
    """
    if framework == "nist_800_131a":
        return _compliance_nist_800_131a(components)
    if framework == "pci_dss_12_3_3":
        return _compliance_pci_dss(components)
    if framework == "dst_2026":
        return _compliance_dst_2026(components)
    if framework == "cnsa_2":
        return _compliance_cnsa_2(components)
    raise ValueError(f"Unknown compliance framework: {framework}")


# ---------------------------------------------------------------------------
# Internal compliance helpers
# ---------------------------------------------------------------------------

def _check_nist_800_131a(
    algorithm: str,
    family: str,
    risk: int,
    key_size: Optional[int],
) -> bool:
    """
    NIST SP 800-131A Rev 2 minimum requirements:
      - RSA ≥ 2048
      - DH ≥ 2048
      - Not SHA-1
      - Not TLS < 1.2 (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
      - Not deprecated algorithms
    """
    a = algorithm.lower()

    if "sha-1" in a or "sha1" in a:
        return False

    if family.upper() == "RSA":
        ks = key_size or 2048
        return ks >= 2048

    if family.upper() == "DH":
        ks = key_size or 2048
        return ks >= 2048

    if family.upper() == "TLS":
        if any(v in a for v in ("ssl_2_0", "ssl_3_0", "tls_1_0", "tls_1_1",
                                 "ssl2", "ssl3", "tls10", "tls11")):
            return False

    return risk <= 5 or family.upper() in ("AES", "SHA", "ML-KEM", "ML-DSA", "SLH-DSA")


def _check_pci_dss(family: str, quantum_status: str) -> bool:
    """
    PCI DSS 12.3.3: requires documented CBOM and quantum-safe migration plan.
    For component-level: FAIL if family is RSA/ECC/DH (quantum-vulnerable asymmetric).
    """
    if quantum_status in ("vulnerable", "deprecated"):
        if family.upper() in ("RSA", "ECC", "DH"):
            return False
    return True


def _check_dst_2026(quantum_status: str) -> bool:
    """
    India DST Task Force 2026 Phase 1: CBOM required.
    Phase 2 (2027): migration plan required.
    FAIL if any component is quantum-vulnerable.
    """
    return quantum_status not in ("vulnerable", "deprecated")


def _check_cnsa_2(family: str, quantum_status: str) -> bool:
    """
    NSA CNSA 2.0: mandates PQC for national security systems.
    FAIL if any asymmetric algorithm is not PQC.
    """
    if family.upper() in ("RSA", "ECC", "DH"):
        return False
    if quantum_status in ("vulnerable", "deprecated"):
        return False
    return True


def _migration_priority(final_risk_score: float, hndl_risk: bool) -> str:
    if hndl_risk or final_risk_score >= 8:
        return "critical"
    if final_risk_score >= 5:
        return "high"
    if final_risk_score >= 2:
        return "medium"
    return "low"


def _recommended_next_step(quantum_status: str, hndl: bool, priority: str) -> str:
    if quantum_status == "safe":
        return "No action required — algorithm is post-quantum safe"
    if hndl:
        return "Immediate migration to ML-KEM (FIPS 203) required — HNDL risk active"
    if priority == "critical":
        return "Migrate to post-quantum algorithm within 90 days"
    if priority == "high":
        return "Schedule migration to post-quantum algorithm within 1 year"
    if priority == "medium":
        return "Include in next security review cycle (1–2 years)"
    return "Monitor — include in long-term quantum migration roadmap"


def _compliance_nist_800_131a(components: list[ComponentRiskScore]) -> ComplianceResult:
    failing = [c.component_id for c in components if not c.nist_compliant]
    if not failing:
        return ComplianceResult("nist_800_131a", "compliant", [], "All algorithms meet NIST SP 800-131A Rev 2 requirements")
    return ComplianceResult(
        "nist_800_131a",
        "non_compliant",
        failing,
        f"{len(failing)} components use algorithms below NIST SP 800-131A Rev 2 minimums "
        f"(RSA<2048, DH<2048, SHA-1, TLS<1.2)",
    )


def _compliance_pci_dss(components: list[ComponentRiskScore]) -> ComplianceResult:
    failing = [c.component_id for c in components if not c.pci_compliant]
    if not failing:
        return ComplianceResult("pci_dss_12_3_3", "compliant", [], "All components compliant with PCI DSS 12.3.3")
    return ComplianceResult(
        "pci_dss_12_3_3",
        "non_compliant",
        failing,
        f"{len(failing)} quantum-vulnerable asymmetric components found. "
        f"PCI DSS 12.3.3 requires a documented quantum migration plan.",
    )


def _compliance_dst_2026(components: list[ComponentRiskScore]) -> ComplianceResult:
    failing = [c.component_id for c in components if not c.dst_compliant]
    if not failing:
        return ComplianceResult("dst_2026", "compliant", [], "No quantum-vulnerable components found")
    return ComplianceResult(
        "dst_2026",
        "non_compliant",
        failing,
        f"{len(failing)} quantum-vulnerable components. India DST Task Force 2026 "
        f"Phase 1 requires a complete CBOM and migration roadmap by end of 2026.",
    )


def _compliance_cnsa_2(components: list[ComponentRiskScore]) -> ComplianceResult:
    failing = [c.component_id for c in components if not c.cnsa_compliant]
    if not failing:
        return ComplianceResult("cnsa_2", "compliant", [], "All components meet NSA CNSA 2.0 requirements")
    return ComplianceResult(
        "cnsa_2",
        "non_compliant",
        failing,
        f"{len(failing)} non-PQC asymmetric components. NSA CNSA 2.0 mandates "
        f"ML-KEM and ML-DSA for all new systems.",
    )
