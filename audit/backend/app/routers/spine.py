"""Platform-spine REST API (PRD 13, Phase 1.5).

Org-scoped, read-only over the crypto-asset graph, plus one explicit write (generate an
attestation). Every read of weakness detail is recorded in the event log (fork E). Resource
lookups by id go through the deps.py verifiers (404-not-403). No GraphQL — a graph-traversal
endpoint (/assets/{id}/edges) covers traversal within the existing FastAPI/REST stack.
"""

import uuid
from datetime import datetime
from typing import Annotated, Optional

import json

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.deps import (
    require_permission,
    verify_asset_belongs_to_org,
    verify_attestation_belongs_to_org,
    verify_evaluation_belongs_to_org,
)
from app.rbac import ATTESTATION_WRITE
from app.models.asset import Asset
from app.models.asset_edge import AssetEdge
from app.models.attestation import Attestation
from app.models.component_state import ComponentState
from app.models.crypto_component import CryptoComponent
from app.models.event import Event
from app.models.organisation import Organisation
from app.models.policy import PolicyEvaluation, Violation
from app.models.user import User
from app.security import get_current_user

router = APIRouter()


# --------------------------------------------------------------------------- DTOs
class AssetNode(BaseModel):
    id: uuid.UUID
    type: str
    name: Optional[str]
    identifier: str
    provenance: str
    status: str
    model_config = {"from_attributes": True}


class EdgeOut(BaseModel):
    id: uuid.UUID
    src_asset_id: uuid.UUID
    dst_asset_id: uuid.UUID
    relation: str
    discovered_by: str
    confidence: float
    valid_from: datetime
    valid_to: Optional[datetime]
    model_config = {"from_attributes": True}


class ComponentStateOut(BaseModel):
    id: uuid.UUID
    asset_id: uuid.UUID
    slot_key: str
    winning_observation_id: uuid.UUID
    latest_policy_evaluation_id: Optional[uuid.UUID]
    conflict: bool
    algorithm: Optional[str] = None
    algorithm_family: Optional[str] = None
    quantum_status: Optional[str] = None
    source: Optional[str] = None
    model_config = {"from_attributes": True}


class EvaluationOut(BaseModel):
    id: uuid.UUID
    policy_id: uuid.UUID
    policy_content_hash: str
    result_hash: str
    violations_count: int
    covered_asset_set: Optional[list] = None
    ran_at: datetime
    model_config = {"from_attributes": True}


class ViolationOut(BaseModel):
    id: uuid.UUID
    evaluation_id: uuid.UUID
    asset_id: uuid.UUID
    rule_key: str
    severity: str
    actual: Optional[str]
    target_state: Optional[str]
    model_config = {"from_attributes": True}


class AttestationOut(BaseModel):
    id: uuid.UUID
    policy_version: str
    policy_content_hash: str
    evaluation_id: uuid.UUID
    evaluation_result_hash: str
    graph_schema_version: int
    key_id: str
    signature: str
    created_at: datetime
    model_config = {"from_attributes": True}


class EventOut(BaseModel):
    id: uuid.UUID
    type: str
    actor: Optional[str]
    asset_id: Optional[uuid.UUID]
    payload: Optional[dict]
    at: datetime
    model_config = {"from_attributes": True}


# ----------------------------------------------------------------------- helpers
async def _audit(db: AsyncSession, user: User, kind: str, asset_id=None, extra=None):
    """Record a sensitive-read in the append-only event log (fork E)."""
    db.add(Event(org_id=user.org_id, type="posture_read", actor=str(user.id),
                 asset_id=asset_id, payload={"read": kind, **(extra or {})}))
    await db.commit()


# ------------------------------------------------------------------------- routes
@router.get("/assets", response_model=list[AssetNode])
async def list_assets(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
    provenance: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    q = select(Asset).where(Asset.org_id == current_user.org_id)
    if provenance:
        q = q.where(Asset.provenance == provenance)
    q = q.order_by(Asset.first_seen_at.desc()).limit(limit).offset(offset)
    return (await db.execute(q)).scalars().all()


@router.get("/assets/{asset_id}", response_model=AssetNode)
async def get_asset(asset: Annotated[Asset, Depends(verify_asset_belongs_to_org)]):
    return asset


@router.get("/assets/{asset_id}/edges", response_model=list[EdgeOut])
async def asset_edges(
    asset: Annotated[Asset, Depends(verify_asset_belongs_to_org)],
    db: AsyncSession = Depends(get_db),
):
    q = select(AssetEdge).where(
        AssetEdge.org_id == asset.org_id,
        or_(AssetEdge.src_asset_id == asset.id, AssetEdge.dst_asset_id == asset.id),
    )
    return (await db.execute(q)).scalars().all()


@router.get("/assets/{asset_id}/state", response_model=list[ComponentStateOut])
async def asset_state(
    asset: Annotated[Asset, Depends(verify_asset_belongs_to_org)],
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    states = (await db.execute(
        select(ComponentState).where(
            ComponentState.org_id == asset.org_id, ComponentState.asset_id == asset.id)
    )).scalars().all()
    out = []
    for st in states:
        obs = await db.get(CryptoComponent, st.winning_observation_id)
        row = ComponentStateOut.model_validate(st)
        if obs:
            row.algorithm = obs.algorithm
            row.algorithm_family = obs.algorithm_family
            row.quantum_status = obs.quantum_status
            row.source = obs.source
        out.append(row)
    await _audit(db, current_user, "asset_state", asset_id=asset.id)
    return out


@router.get("/component-states", response_model=list[ComponentStateOut])
async def list_component_states(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
    conflict: Optional[bool] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    q = select(ComponentState).where(ComponentState.org_id == current_user.org_id)
    if conflict is not None:
        q = q.where(ComponentState.conflict == conflict)
    q = q.limit(limit).offset(offset)
    states = (await db.execute(q)).scalars().all()
    out = []
    for st in states:
        obs = await db.get(CryptoComponent, st.winning_observation_id)
        row = ComponentStateOut.model_validate(st)
        if obs:
            row.algorithm = obs.algorithm
            row.algorithm_family = obs.algorithm_family
            row.quantum_status = obs.quantum_status
            row.source = obs.source
        out.append(row)
    await _audit(db, current_user, "component_states", extra={"count": len(out)})
    return out


@router.get("/evaluations", response_model=list[EvaluationOut])
async def list_evaluations(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    q = (select(PolicyEvaluation).where(PolicyEvaluation.org_id == current_user.org_id)
         .order_by(PolicyEvaluation.ran_at.desc()).limit(limit).offset(offset))
    return (await db.execute(q)).scalars().all()


@router.get("/evaluations/{evaluation_id}/violations", response_model=list[ViolationOut])
async def evaluation_violations(
    evaluation: Annotated[PolicyEvaluation, Depends(verify_evaluation_belongs_to_org)],
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    q = (select(Violation).where(Violation.evaluation_id == evaluation.id)
         .order_by(Violation.severity))
    viols = (await db.execute(q)).scalars().all()
    await _audit(db, current_user, "violations", extra={"evaluation_id": str(evaluation.id)})
    return viols


@router.get("/violations/current", response_model=list[ViolationOut])
async def current_violations(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    latest = (await db.execute(
        select(PolicyEvaluation).where(PolicyEvaluation.org_id == current_user.org_id)
        .order_by(PolicyEvaluation.ran_at.desc()).limit(1)
    )).scalar_one_or_none()
    if not latest:
        return []
    viols = (await db.execute(
        select(Violation).where(Violation.evaluation_id == latest.id)
    )).scalars().all()
    await _audit(db, current_user, "current_violations", extra={"evaluation_id": str(latest.id)})
    return viols


@router.get("/attestations", response_model=list[AttestationOut])
async def list_attestations(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    q = (select(Attestation).where(Attestation.org_id == current_user.org_id)
         .order_by(Attestation.created_at.desc()).limit(limit).offset(offset))
    return (await db.execute(q)).scalars().all()


@router.get("/attestations/{attestation_id}", response_model=AttestationOut)
async def get_attestation(att: Annotated[Attestation, Depends(verify_attestation_belongs_to_org)]):
    return att


@router.get("/attestations/{attestation_id}/download")
async def download_attestation(
    att: Annotated[Attestation, Depends(verify_attestation_belongs_to_org)],
):
    """Download the signed certificate as a standalone JSON file.

    The file is self-contained: it carries the canonical fields, the Ed25519 signature, and
    the public key, so an auditor verifies it fully offline with `seqr verify-attestation`
    (no callback to SeQr). Served as an attachment.
    """
    if not att.artifact_json:
        # Pre-artifact_json row: the exact signed bytes were never persisted, so a
        # reproducible download is impossible. Regenerating is cheap and deterministic.
        raise HTTPException(
            status_code=409,
            detail="This attestation predates certificate storage. Generate a new one.",
        )
    body = json.dumps(att.artifact_json, sort_keys=True, indent=2)
    filename = f"seqr-attestation-{att.id}.json"
    return Response(
        content=body,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/attestations/{attestation_id}/certificate.pdf")
async def attestation_certificate(
    att: Annotated[Attestation, Depends(verify_attestation_belongs_to_org)],
    db: AsyncSession = Depends(get_db),
):
    """Human-readable compliance certificate (PDF) for the signed attestation — the auditor
    filing artifact. Authenticity is still proven offline via the JSON + `seqr verify-attestation`.
    """
    from app.reports.attestation_cert import build_attestation_certificate

    org = (await db.execute(
        select(Organisation).where(Organisation.id == att.org_id)
    )).scalar_one_or_none()
    org_name = org.name if org else str(att.org_id)
    pdf = build_attestation_certificate(att, org_name)
    filename = f"seqr-attestation-{att.id}.pdf"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/attestations")
async def generate_attestation(current_user: Annotated[User, Depends(require_permission(ATTESTATION_WRITE))]):
    """Explicit write: sign an attestation over the org's latest policy evaluation.

    Uses the sync spine (attest/policy modules) in a dedicated session — attestation is a
    deliberate, low-frequency action.
    """
    from app.database import SyncSessionLocal
    from app.spine.attest import create_attestation, get_signer

    scanner_version = None
    try:
        import seqr_scanner
        scanner_version = getattr(seqr_scanner, "__version__", None)
    except Exception:
        pass

    db = SyncSessionLocal()
    try:
        ev = (db.query(PolicyEvaluation)
              .filter(PolicyEvaluation.org_id == current_user.org_id)
              .order_by(PolicyEvaluation.ran_at.desc()).first())
        if not ev:
            raise HTTPException(status_code=404, detail="No policy evaluation to attest. Run a scan first.")
        row, artifact = create_attestation(db, current_user.org_id, ev, get_signer(),
                                           scanner_version=scanner_version, actor=str(current_user.id))
        db.commit()
        return {"attestation_id": str(row.id), "artifact": artifact}
    finally:
        db.close()


@router.get("/events", response_model=list[EventOut])
async def list_events(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
    type: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    q = select(Event).where(Event.org_id == current_user.org_id)
    if type:
        q = q.where(Event.type == type)
    q = q.order_by(Event.at.desc()).limit(limit).offset(offset)
    return (await db.execute(q)).scalars().all()


# ── context-aware risk (risk engine v2) over the org's current component state ──

_HNDL_DISCLAIMER = (
    "HNDL exposure scores are predictive cryptographic risk metrics based on data-type "
    "endurance, not indicators of active data interception or confirmed network breaches."
)


@router.get("/risk")
async def context_risk(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """Rank every current crypto slot by context-aware risk (exposure, role, data, blast radius).

    Org-scoped: assets, states, observations and edges are all filtered by the caller's org.
    """
    from engines.risk_v2 import InfraComponent, assess_component, summarize

    org = current_user.org_id
    assets = {a.id: a for a in (await db.execute(select(Asset).where(Asset.org_id == org))).scalars()}
    edges = (await db.execute(
        select(AssetEdge).where(AssetEdge.org_id == org, AssetEdge.valid_to.is_(None))
    )).scalars().all()
    degree: dict[uuid.UUID, int] = {}
    fronted: set[uuid.UUID] = set()
    for e in edges:
        degree[e.src_asset_id] = degree.get(e.src_asset_id, 0) + 1
        degree[e.dst_asset_id] = degree.get(e.dst_asset_id, 0) + 1
        if e.relation == "origin_of":
            fronted.add(e.dst_asset_id)

    states = (await db.execute(select(ComponentState).where(ComponentState.org_id == org))).scalars().all()
    comps = []
    for st in states:
        obs = await db.get(CryptoComponent, st.winning_observation_id)
        asset = assets.get(st.asset_id)
        if not obs or not asset or obs.org_id != org:
            continue
        comps.append(InfraComponent(
            asset_id=str(asset.id), asset_identifier=asset.identifier, asset_type=(asset.type or "").lower(),
            slot_key=st.slot_key, algorithm=obs.algorithm, algorithm_family=obs.algorithm_family,
            quantum_status=obs.quantum_status, key_size=obs.key_size,
            data_sensitivity=asset.data_sensitivity or "internal",
            dependents=1 + degree.get(asset.id, 0), fronted_by_edge=asset.id in fronted,
            source=obs.source or "", confidence=obs.confidence or "high",
        ))
    pairs = sorted(((assess_component(c), c) for c in comps), key=lambda p: (-p[0].score, p[0].rel_path))
    summary = summarize([a for a, _ in pairs])
    summary["hndl_disclaimer"] = _HNDL_DISCLAIMER
    out = []
    for a, c in pairs:
        d = a.to_dict()
        d.update(asset_id=c.asset_id, asset_type=c.asset_type, slot_key=c.slot_key,
                 source=c.source, reasons=a.reasons(2))
        out.append(d)
    await _audit(db, current_user, "context_risk", extra={"count": len(out)})
    return {"summary": summary, "components": out}
