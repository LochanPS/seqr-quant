"""Graph ingest: turn scan observations into resolved assets, edges, and current state.

Called from the scan write-path after the append-only CryptoComponent observations are
committed. Everything here is org-scoped. Observations are never mutated; only the
projection table (component_state) and the graph (assets/identities/edges) are upserted.
See PRD 13 (forks A, B, D, E).
"""

import uuid
from datetime import datetime

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.asset_edge import AssetEdge
from app.models.asset_identity import AssetIdentity
from app.models.component_state import ComponentState
from app.models.crypto_component import CryptoComponent
from app.models.event import Event
from app.spine.sources import DiscoverySource, precedence_for

# location_type on an observation -> the crypto slot it projects into on the asset.
_SLOT = {
    "tls_cert": "tls:cert",
    "tls_kex": "tls:kex",
    "ssh_key": "ssh:hostkey",
    "ssh_kex": "ssh:kex",
}


def slot_key_for(location_type: str) -> str:
    return _SLOT.get(location_type, location_type)


def _u(v) -> uuid.UUID:
    return v if isinstance(v, uuid.UUID) else uuid.UUID(str(v))


def confidence_score(qualitative: str | None) -> float | None:
    """Map the scanner's qualitative confidence string to a 0..1 score."""
    return {"high": 0.9, "medium": 0.6, "low": 0.3}.get((qualitative or "").lower())


def record_event(db: Session, org_id, type_: str, actor: str | None, asset_id=None, payload=None):
    """Append an immutable event / access-audit row. Never store raw weakness detail."""
    db.add(Event(org_id=_u(org_id), type=type_, actor=actor,
                 asset_id=_u(asset_id) if asset_id else None, payload=payload))


def resolve_asset(db: Session, org_id, key_type: str, key_value: str,
                  asset_type: str = "domain", provenance: str = "discovered",
                  resolver: str = "exact", confidence: float = 1.0) -> uuid.UUID:
    """Natural-key -> Asset UUID (fork A). Reattaches to the existing asset or creates one."""
    org_id = _u(org_id)
    ident = (
        db.query(AssetIdentity)
        .filter(
            AssetIdentity.org_id == org_id,
            AssetIdentity.key_type == key_type,
            AssetIdentity.key_value == key_value,
            AssetIdentity.merged_into.is_(None),
        )
        .first()
    )
    if ident:
        return ident.asset_id

    asset = Asset(org_id=org_id, type=asset_type, identifier=key_value,
                  name=key_value, provenance=provenance, status="discovered")
    db.add(asset)
    db.flush()  # need asset.id
    db.add(AssetIdentity(org_id=org_id, asset_id=asset.id, key_type=key_type,
                         key_value=key_value, resolver=resolver, confidence=confidence))
    return asset.id


def project_component_state(db: Session, org_id, asset_id):
    """Rebuild current state for an asset: per slot, the winning observation (fork B, D).

    Winner = highest source precedence, then most recent observed_at. `conflict` is set when
    different sources disagree on the algorithm for the same slot — the loser is kept, not
    dropped (the observations are append-only).
    """
    org_id, asset_id = _u(org_id), _u(asset_id)
    obs = (
        db.query(CryptoComponent)
        .filter(CryptoComponent.org_id == org_id, CryptoComponent.asset_id == asset_id)
        .all()
    )
    by_slot: dict[str, list] = {}
    for o in obs:
        by_slot.setdefault(slot_key_for(o.location_type), []).append(o)

    for slot, group in by_slot.items():
        group.sort(
            key=lambda o: (precedence_for(o.source or ""), o.observed_at or datetime.min),
            reverse=True,
        )
        winner = group[0]
        conflict = len({o.algorithm for o in group}) > 1 and len({o.source for o in group}) > 1

        cs = (
            db.query(ComponentState)
            .filter(
                ComponentState.org_id == org_id,
                ComponentState.asset_id == asset_id,
                ComponentState.slot_key == slot,
            )
            .first()
        )
        if cs:
            cs.winning_observation_id = winner.id
            cs.conflict = conflict
        else:
            db.add(ComponentState(org_id=org_id, asset_id=asset_id, slot_key=slot,
                                  winning_observation_id=winner.id, conflict=conflict))


def _candidate_key(cand) -> str | None:
    """Best stable key from an origin candidate (dict or string)."""
    if isinstance(cand, dict):
        return cand.get("subdomain") or cand.get("host") or cand.get("ip")
    return str(cand) if cand else None


def ingest_scan_graph(db: Session, org_id, asset_id, scan_id, transport: dict | None = None):
    """Resolve the scanned asset, record origin edges, project state, log the event."""
    org_id, asset_id = _u(org_id), _u(asset_id)

    # Ensure the primary (user-declared) asset has an identity key so rescans resolve to it.
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if asset:
        has_ident = (
            db.query(AssetIdentity)
            .filter(AssetIdentity.org_id == org_id, AssetIdentity.asset_id == asset_id)
            .first()
        )
        if not has_ident:
            key_type = "domain" if asset.type in ("domain", "https") else asset.type
            db.add(AssetIdentity(org_id=org_id, asset_id=asset_id, key_type=key_type,
                                 key_value=asset.identifier, resolver="exact", confidence=1.0))

    # Edge -> origin bypass: when scanning a CDN edge, link to each discovered origin.
    if transport and transport.get("scan_target") == "edge":
        for cand in (transport.get("origin_candidates") or []):
            key = _candidate_key(cand)
            if not key:
                continue
            origin_id = resolve_asset(db, org_id, "host", key, asset_type="origin",
                                      resolver="ct_log", confidence=0.6)
            open_edge = (
                db.query(AssetEdge)
                .filter(
                    AssetEdge.org_id == org_id,
                    AssetEdge.src_asset_id == asset_id,
                    AssetEdge.dst_asset_id == origin_id,
                    AssetEdge.relation == "origin_of",
                    AssetEdge.valid_to.is_(None),
                )
                .first()
            )
            if not open_edge:
                db.add(AssetEdge(org_id=org_id, src_asset_id=asset_id, dst_asset_id=origin_id,
                                 relation="origin_of", discovered_by=DiscoverySource.EXTERNAL_SCANNER,
                                 confidence=0.6))

    project_component_state(db, org_id, asset_id)
    record_event(db, org_id, "measured", "system", asset_id, {"scan_id": str(scan_id)})
