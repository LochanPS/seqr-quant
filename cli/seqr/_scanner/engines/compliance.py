"""
Compliance framework registry for SeQr.

India-first. Every framework below is sourced from a primary government /
standards-body document, with the citation stored in `source` and the real
enforcement status in `enforcement` / `effective_date`. Accuracy here is a
product requirement: SeQr is sold as compliance evidence, so a wrong date or
an overstated mandate is a liability, not a marketing flourish.

CNSA 2.0 (US National Security System mandate) is deliberately excluded — it
does not apply to Indian private companies.

Source verification last reviewed: 2026-06-21. Re-verify against primary
sources before each release — this space moves fast (RBI Q-SAFE report ~Nov
2026, DPDP Phase III 2027-05-13, DST procurement mandate FY2027-28).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ComplianceFramework:
    name: str           # stable identifier used in framework checks / backend / tests
    display_name: str   # full human-readable name
    applies_to: str     # "india" | "us" | "global"
    mandatory: bool     # True = legally or regulatorily required (statutory/binding)
    phase: str          # current enforcement phase: active | phase1 | phase3_pending | monitor | reference

    note: str = ""

    # --- v1.2: audit-grade dating + citation (additive, safe defaults) ---
    enforcement: str = "monitor"   # mandatory | recommendatory | monitor | reference
    effective_date: str = ""       # ISO date the obligation is/becomes enforceable, or ""
    deadline: str = ""             # human-readable key deadline / milestone
    source: str = ""               # primary-source citation


# ---------------------------------------------------------------------------
# India-first compliance frameworks
# ---------------------------------------------------------------------------

PCI_DSS_4X = ComplianceFramework(
    name="PCI_DSS_4X",
    display_name="PCI DSS v4.0.1 — Req 12.3.3",
    applies_to="global",
    mandatory=True,
    phase="active",
    enforcement="mandatory",
    effective_date="2025-03-31",
    deadline="Cryptographic inventory + review at least every 12 months (mandatory since 2025-03-31).",
    source="PCI SSC, PCI DSS v4.0.1, Requirement 12.3.3.",
    note=(
        "Requires a documented inventory of all cipher suites/protocols in use, "
        "active monitoring of their viability, and a documented response plan. "
        "A SeQr CBOM directly satisfies the inventory control."
    ),
)

NIST_FIPS_203_204 = ComplianceFramework(
    name="NIST_FIPS_203_204",
    display_name="NIST FIPS 203/204/205",
    applies_to="global",
    mandatory=False,
    phase="reference",
    enforcement="reference",
    effective_date="2024-08-13",
    deadline="Reference standard — no deadline for Indian private companies.",
    source="NIST FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA), Aug 2024.",
    note=(
        "Reference standard for PQC algorithm selection. Not a mandate for Indian "
        "private companies. Used to name recommended target algorithms."
    ),
)

SEBI_CSCRF = ComplianceFramework(
    name="SEBI_CSCRF",
    display_name="SEBI CSCRF — PQC Migration",
    applies_to="india",
    mandatory=True,
    phase="active",
    enforcement="mandatory",
    effective_date="2025-06-01",
    deadline=(
        "SEBI Regulated Entities: maintain a crypto-asset inventory and prioritise "
        "PQC migration by risk/criticality/data-sensitivity (expectation live since Jun 2025)."
    ),
    source=(
        "SEBI Cybersecurity & Cyber Resilience Framework (CSCRF) for Regulated "
        "Entities, circular 20 Aug 2024; PQC migration expectation added Jun 2025."
    ),
    note=(
        "Binding on SEBI REs (exchanges, brokers, AMCs, mutual funds, RTAs, rating "
        "agencies). Requires inventory of all cryptographic assets (keys, certs, "
        "algorithms) and risk-based PQC prioritisation — exactly the SeQr CBOM output. "
        "CBOM not yet named explicitly; SBOM already required for critical systems."
    ),
)

DST_TASK_FORCE_2026 = ComplianceFramework(
    name="DST_TASK_FORCE_2026",
    display_name="DST Task Force — Quantum-Safe Ecosystem",
    applies_to="india",
    mandatory=False,
    phase="phase1",
    enforcement="recommendatory",
    effective_date="2026-02-04",
    deadline=(
        "CII: governance + cryptographic-asset inventory by 2027; high-priority "
        "systems migrated by 2028; full quantum-safe by 2029. CBOM in government "
        "procurement from FY2027-28. Broader enterprise adoption by ~2033."
    ),
    source=(
        "DST, 'Implementation of Quantum Safe Ecosystem in India — Report of the "
        "Task Force', 4 Feb 2026 (chair: Dr. Rajkumar Upadhyay, C-DOT)."
    ),
    note=(
        "National PQC roadmap. RECOMMENDATORY — it is a task-force report, not a "
        "statute; statutory enforcement rests with sectoral regulators (RBI, SEBI, "
        "DoT). CII per NCIIPC (IT Act s.70A) includes Banking/Financial Services/"
        "Insurance. SeQr builds the cryptographic-asset inventory the 2027 milestone requires."
    ),
)

RBI_IT_FRAMEWORK = ComplianceFramework(
    name="RBI_IT_FRAMEWORK",
    display_name="RBI — Q-SAFE Committee",
    applies_to="india",
    mandatory=False,
    phase="monitor",
    enforcement="monitor",
    effective_date="",
    deadline="Q-SAFE Committee framework expected ~Nov 2026 (6 months from 25 May 2026).",
    source=(
        "RBI press release, 25 May 2026 — 'Quantum Secure and Adaptive Financial "
        "Ecosystem (Q-SAFE)' Expert Committee (convener: Dr. Anil Prabhakar, IIT Madras)."
    ),
    note=(
        "RBI Q-SAFE Committee is reviewing financial-sector cryptographic "
        "infrastructure via CBOM and crypto-agility assessment. No mandatory PQC "
        "deadline for banks/NBFCs yet — framework expected ~Nov 2026. Treat as a "
        "near-term emerging requirement, not a current pass/fail."
    ),
)

CERT_IN = ComplianceFramework(
    name="CERT_IN",
    display_name="CERT-In",
    applies_to="india",
    mandatory=False,
    phase="monitor",
    enforcement="monitor",
    effective_date="",
    deadline="No CERT-In-specific PQC deadline confirmed.",
    source="No CERT-In PQC-specific advisory located as of 2026-06.",
    note=(
        "No mandatory PQC advisory from CERT-In confirmed as of 2026-06. HNDL "
        "assessment rationale is grounded in global guidance (CISA/NIST/NCSC) until "
        "a citable CERT-In document exists. Do not present as an Indian mandate."
    ),
)

DPDP_2023 = ComplianceFramework(
    name="DPDP_2023",
    display_name="DPDP Act 2023 — §8",
    applies_to="india",
    mandatory=True,
    phase="phase3_pending",
    enforcement="mandatory",
    effective_date="2027-05-13",
    deadline=(
        "Section 8 'reasonable security safeguards' and Schedule-1 penalties (up to "
        "Rs.250 crore) become ENFORCEABLE 2027-05-13 (DPDP Rules 2025, Phase III)."
    ),
    source=(
        "DPDP Act 2023, s.8; DPDP Rules 2025 (notified 13 Nov 2025, MeitY); "
        "Phase III effective 18 months later = 2027-05-13."
    ),
    note=(
        "The Act is passed but s.8 obligations and the penalty schedule are NOT yet "
        "enforceable — Phase III lands 2027-05-13. Rule 6 lists encryption among "
        "minimum safeguards. Frame quantum-vulnerable PII transport as a liability "
        "that becomes enforceable 2027-05-13, NOT as a current live penalty."
    ),
)


# Default framework list — no CNSA 2.0 (US NSS mandate, irrelevant to Indian private sector)
DEFAULT_FRAMEWORKS: list[ComplianceFramework] = [
    PCI_DSS_4X,
    SEBI_CSCRF,
    NIST_FIPS_203_204,
    DST_TASK_FORCE_2026,
    RBI_IT_FRAMEWORK,
    CERT_IN,
    DPDP_2023,
]


# ---------------------------------------------------------------------------
# Compliance check results
# ---------------------------------------------------------------------------

MONITOR_STATUS = "MONITOR"
COMPLIANT_STATUS = "COMPLIANT"
NON_COMPLIANT_STATUS = "NON_COMPLIANT"
PARTIAL_STATUS = "PARTIAL"

_FIPS_PQC_FAMILIES = frozenset({"ML-KEM", "ML-DSA", "SLH-DSA"})


@dataclass
class FrameworkCheckResult:
    framework: ComplianceFramework
    status: str   # COMPLIANT | NON_COMPLIANT | PARTIAL | MONITOR
    note: str
    failing_components: list[str]


def check_framework(
    framework: ComplianceFramework,
    components=None,
) -> FrameworkCheckResult:
    """
    Run a compliance check for a single framework.

    For MONITOR / phase3_pending frameworks (RBI, CERT-In, DPDP pre-enforcement),
    always returns MONITOR status with the accurate note. For active frameworks,
    delegates to the relevant check function.
    """
    components = components or []

    if framework.phase in ("monitor", "phase3_pending"):
        return FrameworkCheckResult(
            framework=framework,
            status=MONITOR_STATUS,
            note=framework.note,
            failing_components=[],
        )

    if framework.name == "DST_TASK_FORCE_2026":
        return _check_dst_task_force(framework, components)

    if framework.name == "PCI_DSS_4X":
        return _check_pci_dss_4x(framework, components)

    if framework.name == "SEBI_CSCRF":
        return _check_sebi_cscrf(framework, components)

    if framework.name == "NIST_FIPS_203_204":
        return _check_nist_reference(framework, components)

    return FrameworkCheckResult(
        framework=framework,
        status=MONITOR_STATUS,
        note=f"No automated check implemented for {framework.display_name}",
        failing_components=[],
    )


def _component_ids(components, predicate) -> list[str]:
    return [
        getattr(c, "component_id", getattr(c, "id", str(i)))
        for i, c in enumerate(components)
        if predicate(c)
    ]


def _check_dst_task_force(
    framework: ComplianceFramework,
    components,
) -> FrameworkCheckResult:
    failing = _component_ids(
        components,
        lambda c: getattr(c, "quantum_status", "unknown") in ("vulnerable", "deprecated"),
    )
    if failing:
        return FrameworkCheckResult(
            framework=framework,
            status=NON_COMPLIANT_STATUS,
            note=(
                f"{len(failing)} quantum-vulnerable components found. The DST roadmap "
                "(recommendatory) targets a cryptographic-asset inventory + migration "
                "plan for CII by 2027; a current CBOM is the first deliverable."
            ),
            failing_components=failing,
        )
    return FrameworkCheckResult(
        framework=framework,
        status=COMPLIANT_STATUS,
        note="No quantum-vulnerable components found; cryptographic inventory current.",
        failing_components=[],
    )


def _check_pci_dss_4x(
    framework: ComplianceFramework,
    components,
) -> FrameworkCheckResult:
    failing = _component_ids(
        components,
        lambda c: (getattr(c, "quantum_status", "unknown") in ("vulnerable", "deprecated")
                   and getattr(c, "algorithm_family", "").upper() in ("RSA", "ECC", "DH")),
    )
    if failing:
        return FrameworkCheckResult(
            framework=framework,
            status=NON_COMPLIANT_STATUS,
            note=(
                f"{len(failing)} quantum-vulnerable asymmetric components. PCI DSS "
                "12.3.3 requires a documented cryptographic inventory and viability "
                "monitoring (mandatory since 2025-03-31)."
            ),
            failing_components=failing,
        )
    return FrameworkCheckResult(
        framework=framework,
        status=COMPLIANT_STATUS,
        note="Cryptographic inventory documented; no quantum-vulnerable asymmetric components.",
        failing_components=[],
    )


def _check_sebi_cscrf(
    framework: ComplianceFramework,
    components,
) -> FrameworkCheckResult:
    """
    SEBI CSCRF (live for SEBI REs since Jun 2025): requires a crypto-asset
    inventory and risk-based PQC prioritisation. Having any scanned components
    means an inventory exists; quantum-vulnerable ones must be prioritised.
    """
    if not components:
        return FrameworkCheckResult(
            framework=framework,
            status=NON_COMPLIANT_STATUS,
            note="No cryptographic inventory on record. SEBI CSCRF expects REs to maintain one.",
            failing_components=[],
        )
    failing = _component_ids(
        components,
        lambda c: getattr(c, "quantum_status", "unknown") in ("vulnerable", "deprecated"),
    )
    if failing:
        return FrameworkCheckResult(
            framework=framework,
            status=PARTIAL_STATUS,
            note=(
                f"Inventory exists ({len(components)} components) — satisfies the CSCRF "
                f"inventory expectation. {len(failing)} quantum-vulnerable components "
                "must be prioritised for PQC migration by risk/criticality/sensitivity."
            ),
            failing_components=failing,
        )
    return FrameworkCheckResult(
        framework=framework,
        status=COMPLIANT_STATUS,
        note="Cryptographic inventory current; no quantum-vulnerable components to prioritise.",
        failing_components=[],
    )


def _check_nist_reference(
    framework: ComplianceFramework,
    components,
) -> FrameworkCheckResult:
    """
    NIST FIPS 203/204/205 is a reference standard, not a pass/fail mandate. We
    DO evaluate whether any PQC already deployed uses FIPS-standardised variants
    vs pre-standard ones (e.g. raw Kyber), which is actionable for the customer.
    """
    pqc = [c for c in components if getattr(c, "algorithm_family", "").upper() in _FIPS_PQC_FAMILIES]
    if not pqc:
        return FrameworkCheckResult(
            framework=framework,
            status=PARTIAL_STATUS,
            note=(
                "No PQC algorithms deployed yet. Target FIPS 203 (ML-KEM) for key "
                "exchange and FIPS 204 (ML-DSA) for signatures when migrating."
            ),
            failing_components=[],
        )
    non_fips = _component_ids(
        pqc,
        lambda c: "kyber" in getattr(c, "algorithm", "").lower()
        or "dilithium" in getattr(c, "algorithm", "").lower(),
    )
    if non_fips:
        return FrameworkCheckResult(
            framework=framework,
            status=PARTIAL_STATUS,
            note=(
                f"{len(non_fips)} component(s) use pre-standard PQC names (Kyber/"
                "Dilithium). Confirm they are the FIPS-final parameter sets (ML-KEM/ML-DSA)."
            ),
            failing_components=non_fips,
        )
    return FrameworkCheckResult(
        framework=framework,
        status=COMPLIANT_STATUS,
        note="Deployed PQC uses FIPS-standardised families (ML-KEM/ML-DSA/SLH-DSA).",
        failing_components=[],
    )
