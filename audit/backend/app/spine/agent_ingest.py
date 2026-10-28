"""Discovery-agent ingest: turn agent-reported observations into spine graph state.

The on-prem discovery agent (PRD 15) inventories internal cryptography the external scanner
cannot see — cert stores, TLS listeners, HSM slots, internal PKI, load balancers — and POSTs
normalized observations here. This module is the write-path: it mirrors `ingest_scan_graph`
but for an agent batch rather than a single network/code scan.

Everything is org-scoped and sync (matching the rest of the spine write-path; the router opens
a SyncSessionLocal). Observations are append-only CryptoComponent rows with
source=discovery_agent (precedence 40 — inside beats outside; see spine/sources.py); the
current authoritative posture per slot is projected into ComponentState.

Idempotent: re-POSTing the same batch (same natural key + slot + algorithm + observed_at) does
not duplicate observations, so an agent can safely retry or resume an interrupted upload.
"""

import uuid
from datetime import datetime

from sqlalchemy.orm import Session

from app.models.crypto_component import CryptoComponent
from app.models.event import Event
from app.models.scan import Scan
from app.spine.ingest import (
    _u,
    confidence_score,
    project_component_state,
    record_event,
    resolve_asset,
)
from app.spine.sources import DiscoverySource, precedence_for

_QUANTUM_STATES = {"vulnerable", "hybrid", "safe", "unknown"}

# Coarse family -> quantum status fallback, used only when the agent omits quantum_status.
# The authoritative classifier lives scanner-side; the agent normally sends both.
_PQC_FAMILIES = {"ml-kem", "ml-dsa", "slh-dsa", "kyber", "dilithium", "sphincs", "falcon", "xmss", "lms"}
_CLASSICAL_FAMILIES = {"rsa", "ecc", "ecdsa", "ecdh", "dh", "dsa", "3des", "des", "rc4", "md5", "sha1"}


def _classify(algorithm: str, family: str | None) -> tuple[str, str]:
    """Return (algorithm_family, quantum_status), inferring what the agent did not send."""
    algo = (algorithm or "").lower()
    fam = (family or "").strip()
    fam_l = fam.lower()
    if not fam:
        # Infer a coarse family from the algorithm name.
        for f in list(_PQC_FAMILIES) + list(_CLASSICAL_FAMILIES):
            if f in algo:
                fam = f.upper()
                fam_l = f
                break
        else:
            fam = "unknown"
            fam_l = "unknown"

    if "hybrid" in algo or ("x25519" in algo and any(p in algo for p in ("mlkem", "kyber"))):
        status = "hybrid"
    elif fam_l in _PQC_FAMILIES:
        status = "safe"
    elif fam_l in _CLASSICAL_FAMILIES:
        status = "vulnerable"
    else:
        status = "unknown"
    return fam, status


def _observation_exists(db: Session, org_id, asset_id, location_type, algorithm, observed_at) -> bool:
    """Idempotency guard: same asset + slot + algorithm + observed_at from the agent already stored."""
    return (
        db.query(CryptoComponent.id)
        .filter(
            CryptoComponent.org_id == org_id,
            CryptoComponent.asset_id == asset_id,
            CryptoComponent.location_type == location_type,
            CryptoComponent.algorithm == algorithm,
            CryptoComponent.observed_at == observed_at,
            CryptoComponent.source == DiscoverySource.DISCOVERY_AGENT.value,
        )
        .first()
        is not None
    )


def ingest_agent_batch(db: Session, org_id, actor: str, observations: list[dict],
                       agent_name: str | None = None) -> dict:
    """Ingest a batch of agent observations into the spine graph. Returns a summary.

    Each observation is a normalized dict with at least: asset_key, location_type,
    location_detail, algorithm. Optional: asset_key_type, asset_type, asset_name,
    algorithm_family, key_size, quantum_status, confidence, observed_at, cert_expiry_date,
    cert_issuer, plugin.

    Creates one Scan row for the batch (an agent upload is a measurement run), inserts the
    append-only observations under it, resolves/creates the target assets, projects current
    state for every touched asset, and appends a `measured` event. Commits at the end.
    """
    org_id = _u(org_id)
    precedence = precedence_for(DiscoverySource.DISCOVERY_AGENT)

    scan = Scan(org_id=org_id, asset_id=None, type="agent", status="complete",
                trigger="agent", started_at=datetime.utcnow(), completed_at=datetime.utcnow())
    db.add(scan)
    db.flush()  # need scan.id

    touched: set[uuid.UUID] = set()
    ingested = 0
    skipped = 0
    vulnerable = 0

    for o in observations:
        asset_key = o["asset_key"]
        key_type = o.get("asset_key_type") or "host"
        asset_type = o.get("asset_type") or "host"
        asset_id = resolve_asset(
            db, org_id, key_type, asset_key, asset_type=asset_type,
            provenance="discovered", resolver="agent", confidence=0.9,
        )

        location_type = o["location_type"]
        observed_at = o.get("observed_at") or datetime.utcnow()
        if isinstance(observed_at, str):
            observed_at = datetime.fromisoformat(observed_at)
        algorithm = o["algorithm"]

        if _observation_exists(db, org_id, asset_id, location_type, algorithm, observed_at):
            skipped += 1
            touched.add(asset_id)
            continue

        family, status = _classify(algorithm, o.get("algorithm_family"))
        if o.get("quantum_status") in _QUANTUM_STATES:
            status = o["quantum_status"]
        if status == "vulnerable":
            vulnerable += 1

        db.add(CryptoComponent(
            org_id=org_id, scan_id=scan.id, asset_id=asset_id,
            location_type=location_type,
            location_detail=o.get("location_detail") or asset_key,
            algorithm=algorithm, algorithm_family=family, key_size=o.get("key_size"),
            quantum_status=status,
            confidence=o.get("confidence"),
            cert_expiry_date=o.get("cert_expiry_date"),
            cert_issuer=o.get("cert_issuer"),
            source=DiscoverySource.DISCOVERY_AGENT.value,
            precedence=precedence,
            confidence_score=confidence_score(o.get("confidence")) or 0.9,
            observed_at=observed_at,
        ))
        ingested += 1
        touched.add(asset_id)

    scan.components_found = ingested
    scan.vulnerable_found = vulnerable
    db.flush()

    for asset_id in touched:
        project_component_state(db, org_id, asset_id)

    record_event(db, org_id, "measured", actor, None, {
        "source": DiscoverySource.DISCOVERY_AGENT.value,
        "agent": agent_name,
        "scan_id": str(scan.id),
        "ingested": ingested,
        "skipped": skipped,
        "assets_touched": len(touched),
    })
    db.commit()

    return {
        "scan_id": str(scan.id),
        "ingested": ingested,
        "skipped_duplicates": skipped,
        "assets_touched": len(touched),
        "vulnerable_found": vulnerable,
    }


def agent_status(db: Session, org_id) -> dict:
    """Observability for the org's agent-sourced posture (PRD 15 §9): coverage + freshness."""
    org_id = _u(org_id)
    q = db.query(CryptoComponent).filter(
        CryptoComponent.org_id == org_id,
        CryptoComponent.source == DiscoverySource.DISCOVERY_AGENT.value,
    )
    obs = q.all()
    assets = {o.asset_id for o in obs if o.asset_id is not None}
    coverage = sorted({o.location_type for o in obs})
    last_event = (
        db.query(Event)
        .filter(Event.org_id == org_id, Event.type == "measured")
        .order_by(Event.at.desc())
        .first()
    )
    last_seen = None
    if obs:
        last_seen = max(o.observed_at for o in obs if o.observed_at)
    return {
        "observations": len(obs),
        "assets_covered": len(assets),
        "plugin_coverage": coverage,
        "last_observed_at": last_seen.isoformat() if last_seen else None,
        "last_event_at": last_event.at.isoformat() if last_event and last_event.at else None,
    }
