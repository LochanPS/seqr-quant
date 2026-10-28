"""Discovery-agent plane REST API (PRD 15) — org-scoped.

Two audiences on one router:

  * The agent itself authenticates with an `agent`-scoped sq_live_ key and pushes internal
    crypto-posture observations into the spine graph (feature-flagged `AGENT_INGEST_ENABLED`).
      POST /api/v1/agent/observations   ingest a batch
      GET  /api/v1/agent/status         its org's agent coverage + freshness

  * An org admin manages the agent credentials from the dashboard (always available):
      POST   /api/v1/agent/credentials        mint an agent credential (raw key shown once)
      GET    /api/v1/agent/credentials         list connected agents (prefix, last-seen)
      DELETE /api/v1/agent/credentials/{id}    revoke a credential

The ingest write runs in a dedicated sync session (the spine write-path is sync), mirroring
the migration + attestation routers. Nothing here changes customer infrastructure — the agent
is read-only discovery; migration stays bundle + runbook.
"""

import hashlib
import secrets
import uuid
from datetime import date, datetime
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models.api_key import APIKey
from app.models.user import User
from app.security import AgentPrincipal, get_current_agent, get_current_user

router = APIRouter()

# Cap a single upload so a runaway agent can't bloat the graph in one call.
_MAX_OBSERVATIONS = 5000


# --------------------------------------------------------------- ingest schemas
class AgentObservationIn(BaseModel):
    asset_key: str = Field(..., min_length=1, max_length=512)
    asset_key_type: str = Field("host", max_length=64)
    asset_type: str = Field("host", max_length=64)
    asset_name: Optional[str] = Field(None, max_length=512)
    location_type: str = Field(..., min_length=1, max_length=64)
    location_detail: Optional[str] = Field(None, max_length=1024)
    algorithm: str = Field(..., min_length=1, max_length=128)
    algorithm_family: Optional[str] = Field(None, max_length=64)
    key_size: Optional[int] = Field(None, ge=0, le=1_000_000)
    quantum_status: Optional[str] = Field(None, max_length=32)
    confidence: Optional[str] = Field(None, max_length=16)
    observed_at: Optional[datetime] = None
    cert_expiry_date: Optional[date] = None
    cert_issuer: Optional[str] = Field(None, max_length=512)
    plugin: Optional[str] = Field(None, max_length=64)


class AgentBatchIn(BaseModel):
    agent: Optional[str] = Field(None, max_length=128)
    observations: list[AgentObservationIn] = Field(default_factory=list)


class AgentImportEnvelope(BaseModel):
    """Signed, zero-egress upload (PRD 15 §8). The agent writes this to a file offline; an
    operator uploads it here. The signature covers the canonical encoding of `observations`."""
    version: int = Field(1, ge=1)
    agent: Optional[str] = Field(None, max_length=128)
    key_prefix: str = Field(..., min_length=1, max_length=64)
    signed_at: Optional[datetime] = None
    observations: list[AgentObservationIn] = Field(default_factory=list)
    signature: str = Field(..., min_length=1, max_length=1024)


class AgentIngestResult(BaseModel):
    scan_id: str
    ingested: int
    skipped_duplicates: int
    assets_touched: int
    vulnerable_found: int


# --------------------------------------------------------------- credential schemas
class AgentCredentialCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    expires_at: Optional[datetime] = None


class AgentCredentialOut(BaseModel):
    model_config = {"from_attributes": True}
    id: uuid.UUID
    name: str
    key_prefix: str
    last_used_at: Optional[datetime]
    expires_at: Optional[datetime]
    created_at: datetime


class AgentCredentialCreated(AgentCredentialOut):
    key: str  # the raw sq_live_ key — shown exactly once, never stored in clear


# =============================================================== agent-facing
async def _raw_observations(request: Request) -> list:
    """The observation list exactly as it arrived on the wire — what the agent signed.
    Verifying the parsed/re-serialized model would drift from the agent's canonical bytes."""
    try:
        body = await request.json()
    except Exception:
        return []
    obs = body.get("observations") if isinstance(body, dict) else None
    return obs if isinstance(obs, list) else []


@router.post("/observations", response_model=AgentIngestResult, status_code=201)
async def push_observations(
    body: AgentBatchIn,
    request: Request,
    agent: Annotated[AgentPrincipal, Depends(get_current_agent)],
    db: AsyncSession = Depends(get_db),
    x_agent_signature: Annotated[Optional[str], Header()] = None,
    x_agent_public_key: Annotated[Optional[str], Header()] = None,
):
    """Ingest a batch of internal crypto-posture observations from a discovery agent.

    Signing (PRD 15 §5/§6): if the credential already carries a public key, the batch MUST be
    signed (``X-Agent-Signature``) and the signature must verify over the observations (401
    otherwise). If it carries no key yet and ``X-Agent-Public-Key`` is supplied, that key is
    trusted-on-first-use and bound to the credential for every future upload.
    """
    if not settings.AGENT_INGEST_ENABLED:
        raise HTTPException(status_code=403, detail="Agent ingestion is disabled on this deployment")
    if len(body.observations) > _MAX_OBSERVATIONS:
        raise HTTPException(status_code=413, detail=f"too many observations (max {_MAX_OBSERVATIONS})")
    if not body.observations:
        raise HTTPException(status_code=400, detail="no observations in batch")

    from app.spine import agent_sig

    credential = await db.get(APIKey, agent.key_id)
    if credential is not None and credential.agent_public_key:
        raw_obs = await _raw_observations(request)
        if not x_agent_signature:
            raise HTTPException(status_code=401, detail="Signature required: this agent credential is key-bound")
        if not agent_sig.verify(credential.agent_public_key, x_agent_signature, raw_obs):
            raise HTTPException(status_code=401, detail="Agent signature verification failed")
    elif credential is not None and x_agent_public_key:
        # Trust-on-first-use: bind this key to the credential for all future uploads.
        credential.agent_public_key = x_agent_public_key.strip()
        await db.commit()

    from app.database import SyncSessionLocal
    from app.spine.agent_ingest import ingest_agent_batch

    payload = [o.model_dump() for o in body.observations]
    db = SyncSessionLocal()
    try:
        result = ingest_agent_batch(db, agent.org_id, agent.actor, payload, agent_name=body.agent)
        # Judge the freshly-updated posture against the org policy (never fails the upload).
        try:
            from app.spine.policy import evaluate_policy
            evaluate_policy(db, agent.org_id)
            db.commit()
        except Exception:
            db.rollback()
        return result
    finally:
        db.close()


@router.get("/status")
async def agent_self_status(agent: Annotated[AgentPrincipal, Depends(get_current_agent)]):
    """Coverage + freshness of this org's agent-sourced posture (PRD 15 §9)."""
    from app.database import SyncSessionLocal
    from app.spine.agent_ingest import agent_status

    db = SyncSessionLocal()
    try:
        return {"agent": agent.name, **agent_status(db, agent.org_id)}
    finally:
        db.close()


# =============================================================== air-gap import
@router.post("/import", response_model=AgentIngestResult, status_code=201)
async def import_signed_envelope(
    body: AgentImportEnvelope,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """Zero-egress air-gap import (PRD 15 §8): an operator uploads a batch the offline agent
    signed to a file. The caller is an org admin; the batch is bound to the agent credential
    named by ``key_prefix`` and accepted only if the credential's key verifies the signature.

    404 an unknown key_prefix, 400 a tampered/invalid signature. Idempotent (existing dedupe).
    """
    _require_admin(current_user)
    if len(body.observations) > _MAX_OBSERVATIONS:
        raise HTTPException(status_code=413, detail=f"too many observations (max {_MAX_OBSERVATIONS})")
    if not body.observations:
        raise HTTPException(status_code=400, detail="no observations in envelope")

    from app.spine import agent_sig

    # Candidate agent credentials in the caller's org that match the prefix and carry a key.
    rows = (await db.execute(
        select(APIKey).where(
            APIKey.org_id == current_user.org_id,
            APIKey.key_prefix == body.key_prefix,
        )
    )).scalars().all()
    candidates = [k for k in rows if "agent" in (k.scopes or []) and k.agent_public_key]
    if not candidates:
        raise HTTPException(status_code=404, detail="No key-bound agent credential for that key_prefix")

    # Verify over the observations exactly as signed (raw wire form), against each candidate key.
    raw = await request.json()
    raw_obs = raw.get("observations") if isinstance(raw, dict) else None
    raw_obs = raw_obs if isinstance(raw_obs, list) else []
    matched = next(
        (k for k in candidates if agent_sig.verify(k.agent_public_key, body.signature, raw_obs)),
        None,
    )
    if matched is None:
        raise HTTPException(status_code=400, detail="Envelope signature verification failed")

    from app.database import SyncSessionLocal
    from app.spine.agent_ingest import ingest_agent_batch

    payload = [o.model_dump() for o in body.observations]
    actor = f"agent:{matched.key_prefix}"
    db_sync = SyncSessionLocal()
    try:
        result = ingest_agent_batch(db_sync, matched.org_id, actor, payload, agent_name=body.agent)
        try:
            from app.spine.policy import evaluate_policy
            evaluate_policy(db_sync, matched.org_id)
            db_sync.commit()
        except Exception:
            db_sync.rollback()
        return result
    finally:
        db_sync.close()


# =============================================================== admin-facing
def _require_admin(user: User) -> None:
    if getattr(user, "role", None) != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")


@router.post("/credentials", response_model=AgentCredentialCreated, status_code=201)
async def create_agent_credential(
    body: AgentCredentialCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """Mint an `agent`-scoped credential for a new discovery agent. Raw key returned once."""
    _require_admin(current_user)

    raw_key = f"sq_live_{secrets.token_urlsafe(18)}"
    api_key = APIKey(
        org_id=current_user.org_id,
        user_id=current_user.id,
        name=body.name,
        key_hash=hashlib.sha256(raw_key.encode()).hexdigest(),
        key_prefix=raw_key[:8],
        scopes=["agent"],
        expires_at=body.expires_at,
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)
    return AgentCredentialCreated(
        id=api_key.id, name=api_key.name, key_prefix=api_key.key_prefix,
        last_used_at=api_key.last_used_at, expires_at=api_key.expires_at,
        created_at=api_key.created_at, key=raw_key,
    )


@router.get("/credentials", response_model=list[AgentCredentialOut])
async def list_agent_credentials(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """List the org's agent credentials (connected agents), newest first."""
    rows = (await db.execute(
        select(APIKey).where(APIKey.org_id == current_user.org_id).order_by(APIKey.created_at.desc())
    )).scalars().all()
    return [k for k in rows if "agent" in (k.scopes or [])]


@router.get("/coverage")
async def agent_coverage(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """Org agent-posture coverage for the dashboard Connections console (PRD 15 §9).

    Same summary as the agent-facing GET /status, but authenticated as an org user (JWT) and
    scoped to the caller's org — the dashboard admin has no agent key. Read runs on the sync
    spine session like the ingest write-path.
    """
    from app.database import SyncSessionLocal
    from app.spine.agent_ingest import agent_status

    dbs = SyncSessionLocal()
    try:
        return {"agent": None, **agent_status(dbs, current_user.org_id)}
    finally:
        dbs.close()


@router.delete("/credentials/{credential_id}", status_code=204)
async def revoke_agent_credential(
    credential_id: uuid.UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """Revoke (delete) an agent credential. 404 (not 403) on a cross-tenant id."""
    _require_admin(current_user)
    key = await db.get(APIKey, credential_id)
    if not key or key.org_id != current_user.org_id or "agent" not in (key.scopes or []):
        raise HTTPException(status_code=404, detail="Agent credential not found")
    await db.delete(key)
    await db.commit()
