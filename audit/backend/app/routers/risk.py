import uuid
from datetime import datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.crypto_component import CryptoComponent
from app.models.scan import Scan
from app.models.user import User
from app.security import get_current_user

router = APIRouter()

_TIMELINE_LABELS = {
    "IMMEDIATE": "Fix within 30 days",
    "URGENT": "Fix within 6 months",
    "PLANNED": "Plan migration by 2027-2030",
    "ROADMAP": "Monitor — already ahead",
}


def _compute_score(components: list) -> int:
    """Pure function: compute org risk score (0-100) from a list of vulnerable CryptoComponents."""
    if not components:
        return 0
    total_weight = 0.0
    weighted_sum = 0.0
    for c in components:
        score = c.pqc_migration_priority or 0.0
        exp = getattr(c, "estimated_hndl_exposure", None)
        weight = 2.0 if exp == "high" else (1.5 if exp == "medium" else 1.0)
        weighted_sum += score * weight
        total_weight += weight
    if total_weight == 0:
        return 0
    return round((weighted_sum / total_weight) * 10)


async def compute_org_risk_score(org_id: str, db: AsyncSession) -> int:
    result = await db.execute(
        select(CryptoComponent)
        .where(CryptoComponent.org_id == uuid.UUID(org_id))
        .where(CryptoComponent.quantum_status == "vulnerable")
    )
    return _compute_score(result.scalars().all())


def _score_label(score: int) -> str:
    if score <= 25:
        return "low"
    if score <= 50:
        return "medium"
    if score <= 75:
        return "high"
    return "critical"


def _get_action_effort(c: CryptoComponent) -> tuple[str, str]:
    algo = (c.algorithm or "").upper()
    loc = (c.location_type or "").lower()

    if "TLS 1.0" in algo or "TLS 1.1" in algo or "TLSV1.0" in algo or "TLSV1.1" in algo:
        return "Disable TLS 1.0 and 1.1 immediately", "1-2 hours"

    if loc == "tls_cert":
        if "RSA" in algo:
            return "Replace certificate with ML-DSA-65 at next renewal (FIPS 204)", "2-4 hours at next renewal"
        if "ECDSA" in algo or "ECC" in algo or algo.startswith("EC"):
            return "Replace certificate with ML-DSA-65 at next renewal (FIPS 204)", "2-4 hours at next renewal"

    if "X25519" in algo:
        return "Add X25519Kyber768 hybrid group alongside X25519", "1-2 days (CDN config change)"

    if loc in ("kex", "key_exchange"):
        if "RSA" in algo:
            return "Replace RSA key exchange with ML-KEM-768 (FIPS 203)", "1-2 days (CDN config change)"

    if "RSA" in algo:
        return "Replace RSA with ML-KEM-768 or ML-DSA-65 (FIPS 203/204)", "3-8 hours per file"

    return "Review and migrate to post-quantum algorithm", "Varies"


@router.get("/score")
async def risk_score(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    all_result = await db.execute(
        select(CryptoComponent).where(CryptoComponent.org_id == current_user.org_id)
    )
    all_components = all_result.scalars().all()

    vulnerable = [c for c in all_components if c.quantum_status == "vulnerable"]
    hndl_high = [c for c in all_components if c.estimated_hndl_exposure == "high"]

    score = _compute_score(vulnerable)

    return {
        "score": score,
        "label": _score_label(score),
        "total_components": len(all_components),
        "vulnerable_count": len(vulnerable),
        "hndl_high_count": len(hndl_high),
        "computed_at": datetime.utcnow().isoformat(),
    }


@router.get("/hndl")
async def hndl_list(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(CryptoComponent)
        .where(CryptoComponent.org_id == current_user.org_id)
        .where(CryptoComponent.estimated_hndl_exposure == "high")
        .order_by(CryptoComponent.pqc_migration_priority.desc())
    )
    components = result.scalars().all()
    return [
        {
            "id": str(c.id),
            "algorithm": c.algorithm,
            "algorithm_family": c.algorithm_family,
            "location_detail": c.location_detail,
            "quantum_status": c.quantum_status,
            "pqc_migration_priority": c.pqc_migration_priority,
            "estimated_hndl_exposure": c.estimated_hndl_exposure,
            "threat_timeline": c.threat_timeline,
        }
        for c in components
    ]


@router.get("/compliance")
async def compliance_status(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    now = datetime.utcnow()

    scans = (await db.execute(
        select(Scan).where(Scan.org_id == current_user.org_id)
    )).scalars().all()

    components = (await db.execute(
        select(CryptoComponent).where(CryptoComponent.org_id == current_user.org_id)
    )).scalars().all()

    completed_scans = [s for s in scans if s.status == "complete"]
    total_docs = len(components)

    # PCI DSS 12.3.3
    if completed_scans:
        pci_status = "PASS"
        pci_message = f"Cryptographic inventory required by PCI DSS 12.3.3. {total_docs} components documented."
    else:
        pci_status = "FAIL"
        pci_message = "Cryptographic inventory required by PCI DSS 12.3.3. No completed scans yet."

    # NIST FIPS 203/204
    immediate_rsa_ecc = [
        c for c in components
        if c.algorithm_family in ("RSA", "ECC") and c.threat_timeline == "IMMEDIATE"
    ]
    planned_rsa_ecc = [
        c for c in components
        if c.algorithm_family in ("RSA", "ECC") and c.threat_timeline in ("PLANNED", "ROADMAP")
    ]
    if not immediate_rsa_ecc:
        if planned_rsa_ecc:
            nist_status = "PLANNED"
        else:
            nist_status = "PASS"
    else:
        nist_status = "PARTIAL"
    nist_message = "Reference standard. Begin migration planning."

    # SEBI CSCRF — live PQC migration expectation for SEBI REs since Jun 2025:
    # maintain a crypto-asset inventory + prioritise PQC by risk. The inventory
    # itself satisfies the core control; vulnerable components must be prioritised.
    vulnerable_comps = [c for c in components if c.quantum_status in ("vulnerable", "deprecated")]
    if not completed_scans:
        sebi_status = "FAIL"
        sebi_message = "SEBI CSCRF expects a cryptographic-asset inventory. No completed scans yet."
    elif vulnerable_comps:
        sebi_status = "PARTIAL"
        sebi_message = (
            f"Inventory satisfies the CSCRF control. {len(vulnerable_comps)} quantum-vulnerable "
            "components must be prioritised for PQC migration (binding on SEBI REs since Jun 2025)."
        )
    else:
        sebi_status = "PASS"
        sebi_message = "Cryptographic inventory current; no quantum-vulnerable components to prioritise."

    # DST Task Force — RECOMMENDATORY (task-force report, 4 Feb 2026), not a statute.
    # CII (incl. BFSI per NCIIPC) target: cryptographic-asset inventory by 2027.
    recent_cutoff = now - timedelta(days=180)
    recent_scans = [
        s for s in completed_scans
        if s.completed_at and s.completed_at >= recent_cutoff
    ]
    if recent_scans:
        dst_status = "PASS"
        dst_detail = "Cryptographic inventory completed within last 180 days."
    else:
        dst_status = "FAIL"
        dst_detail = "No cryptographic inventory scan in the last 180 days."
    dst_message = (
        "Recommendatory roadmap. CII target: cryptographic-asset inventory by 2027, "
        f"CBOM in govt procurement from FY2027-28. {dst_detail}"
    )

    return {
        "PCI_DSS_12_3_3": {
            "status": pci_status,
            "message": pci_message,
            "checked_at": now.isoformat(),
        },
        "SEBI_CSCRF": {
            "status": sebi_status,
            "message": sebi_message,
            "checked_at": now.isoformat(),
        },
        "NIST_FIPS": {
            "status": nist_status,
            "message": nist_message,
            "checked_at": now.isoformat(),
        },
        "DST_TASK_FORCE_2026": {
            "status": dst_status,
            "message": dst_message,
            "checked_at": now.isoformat(),
        },
        "RBI_IT_FRAMEWORK": {
            "status": "MONITOR",
            "message": (
                "RBI Q-SAFE Committee (formed 25 May 2026) reviewing financial-sector "
                "cryptography via CBOM + crypto-agility. Framework expected ~Nov 2026."
            ),
            "checked_at": now.isoformat(),
        },
        "CERT_IN": {
            "status": "MONITOR",
            "message": "No CERT-In-specific PQC advisory confirmed. Monitor for future guidance.",
            "checked_at": now.isoformat(),
        },
        "DPDP_2023": {
            "status": "MONITOR",
            "message": (
                "DPDP Act s.8 safeguards + penalties (up to Rs.250 crore) become "
                "enforceable 2027-05-13 (DPDP Rules 2025, Phase III). Not yet live."
            ),
            "checked_at": now.isoformat(),
        },
    }


@router.get("/roadmap")
async def migration_roadmap(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    components = (await db.execute(
        select(CryptoComponent).where(CryptoComponent.org_id == current_user.org_id)
    )).scalars().all()

    buckets: dict[str, list] = {tl: [] for tl in _TIMELINE_LABELS}

    for c in components:
        tl = c.threat_timeline or "ROADMAP"
        if tl not in buckets:
            tl = "ROADMAP"
        action, effort = _get_action_effort(c)
        buckets[tl].append({
            "id": str(c.id),
            "location": c.location_detail,
            "algorithm": c.algorithm,
            "action": action,
            "effort_hours": effort,
        })

    return {
        tl: {
            "label": label,
            "count": len(buckets[tl]),
            "components": buckets[tl],
        }
        for tl, label in _TIMELINE_LABELS.items()
    }
