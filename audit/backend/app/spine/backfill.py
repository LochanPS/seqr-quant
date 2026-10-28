"""Backfill historical scans into the platform-spine graph (PRD 13, Phase 1 final).

Existing crypto_components rows already ARE the append-only observations — this does NOT
create duplicate observations. It performs a one-time enrichment of legacy rows (correct
observed_at to the scan's real time; infer the structured source/precedence that predates
the columns), then resolves identities, builds temporal edges, rebuilds component_state, and
runs a deterministic policy evaluation per org.

Idempotent: re-running resolves to the same assets/edges and re-projects/re-evaluates without
duplicating. It deliberately does NOT create attestations — those stay explicit user actions.

Usage: python -m app.spine.backfill
"""

import uuid

from sqlalchemy.orm import Session

from app.models.asset_edge import AssetEdge
from app.models.crypto_component import CryptoComponent
from app.models.scan import Scan
from app.spine.ingest import (
    _candidate_key,
    project_component_state,
    record_event,
    resolve_asset,
)
from app.spine.policy import evaluate_policy
from app.spine.sources import DiscoverySource, precedence_for


def _infer_source(c: CryptoComponent) -> str:
    """Legacy rows: a hybrid PQC key exchange came from the active probe; everything else
    was seen by the passive external scanner."""
    if c.location_type in ("tls_kex", "ssh_kex") and (c.algorithm_family or "") == "ML-KEM":
        return DiscoverySource.ACTIVE_PROBE
    return DiscoverySource.EXTERNAL_SCANNER


def _ensure_identity(db: Session, org_id, asset_id):
    from app.models.asset import Asset
    from app.models.asset_identity import AssetIdentity

    exists = (
        db.query(AssetIdentity)
        .filter(AssetIdentity.org_id == org_id, AssetIdentity.asset_id == asset_id)
        .first()
    )
    if exists:
        return
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        return
    key_type = "domain" if asset.type in ("domain", "https") else asset.type
    db.add(AssetIdentity(org_id=org_id, asset_id=asset_id, key_type=key_type,
                         key_value=asset.identifier, resolver="exact", confidence=1.0))


def _origin_edges(db: Session, org_id, asset_id, transport: dict | None):
    if not transport or transport.get("scan_target") != "edge":
        return
    for cand in (transport.get("origin_candidates") or []):
        key = _candidate_key(cand)
        if not key:
            continue
        origin_id = resolve_asset(db, org_id, "host", key, asset_type="origin",
                                  resolver="ct_log", confidence=0.6)
        open_edge = (
            db.query(AssetEdge)
            .filter(AssetEdge.org_id == org_id, AssetEdge.src_asset_id == asset_id,
                    AssetEdge.dst_asset_id == origin_id, AssetEdge.relation == "origin_of",
                    AssetEdge.valid_to.is_(None))
            .first()
        )
        if not open_edge:
            db.add(AssetEdge(org_id=org_id, src_asset_id=asset_id, dst_asset_id=origin_id,
                             relation="origin_of", discovered_by=DiscoverySource.EXTERNAL_SCANNER,
                             confidence=0.6))


def backfill(db: Session) -> dict:
    """Backfill all historical scans. Returns a small summary."""
    scans = db.query(Scan).order_by(Scan.created_at).all()
    touched_assets: set[tuple] = set()
    orgs: set = set()

    # Pass 1 — enrich legacy observations (once), resolve identities, build edges.
    for scan in scans:
        orgs.add(scan.org_id)
        when = scan.completed_at or scan.created_at
        for c in db.query(CryptoComponent).filter(CryptoComponent.scan_id == scan.id).all():
            if when:
                c.observed_at = when  # correct the migration default to the real scan time
            c.source = _infer_source(c)
            c.precedence = precedence_for(c.source)
        if scan.asset_id:
            _ensure_identity(db, scan.org_id, scan.asset_id)
            _origin_edges(db, scan.org_id, scan.asset_id, scan.transport_summary)
            touched_assets.add((scan.org_id, scan.asset_id))
    db.flush()

    # Pass 2 — rebuild current state from the enriched observations.
    for org_id, asset_id in touched_assets:
        project_component_state(db, org_id, asset_id)

    # Pass 3 — one deterministic policy evaluation per org.
    for org_id in orgs:
        evaluate_policy(db, org_id)
        record_event(db, org_id, "backfilled", "system", None, {"scans": len(scans)})

    db.commit()
    return {"scans": len(scans), "assets": len(touched_assets), "orgs": len(orgs)}


def main() -> int:
    from app.database import SyncSessionLocal

    db = SyncSessionLocal()
    try:
        summary = backfill(db)
        print(f"backfill complete: {summary}")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
