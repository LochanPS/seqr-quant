"""
Platform operator console — for SeQr Labs staff (OPERATOR_EMAILS), not customers.

Every route requires `require_operator`. Lets the operator see all organisations
+ usage, change plans, and suspend/reactivate accounts. Tenant boundaries do NOT
apply here (this is the platform-level view), so it is gated strictly by operator
identity.
"""
import re
import uuid
from datetime import datetime
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.asset import Asset
from app.models.blog_post import BlogPost
from app.models.organisation import Organisation
from app.models.scan import Scan
from app.models.user import User
from app.security import require_operator

router = APIRouter()

_VALID_PLANS = {"trial", "small", "mid", "large", "enterprise"}
_VALID_STATUS = {"active", "suspended"}
_VALID_POST_STATUS = {"draft", "published"}


def _slugify(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return s or "post"


class OrgAdminOut(BaseModel):
    id: uuid.UUID
    name: str
    sector: Optional[str]
    plan: str
    status: str
    quantum_risk_score: Optional[int]
    user_count: int
    asset_count: int
    scan_count: int
    last_scan_at: Optional[datetime]
    created_at: datetime


class OrgPatch(BaseModel):
    plan: Optional[str] = None
    status: Optional[str] = None


async def _counts(db: AsyncSession):
    """Return per-org count maps in three grouped queries (avoids N+1)."""
    users = dict((await db.execute(
        select(User.org_id, func.count()).group_by(User.org_id)
    )).all())
    assets = dict((await db.execute(
        select(Asset.org_id, func.count()).group_by(Asset.org_id)
    )).all())
    scan_rows = (await db.execute(
        select(Scan.org_id, func.count(), func.max(Scan.created_at)).group_by(Scan.org_id)
    )).all()
    scans = {r[0]: r[1] for r in scan_rows}
    last_scan = {r[0]: r[2] for r in scan_rows}
    return users, assets, scans, last_scan


@router.get("/orgs", response_model=list[OrgAdminOut])
async def list_orgs(
    _op: Annotated[User, Depends(require_operator)],
    db: AsyncSession = Depends(get_db),
):
    orgs = (await db.execute(select(Organisation).order_by(Organisation.created_at.desc()))).scalars().all()
    users, assets, scans, last_scan = await _counts(db)
    return [
        OrgAdminOut(
            id=o.id, name=o.name, sector=o.sector, plan=o.plan,
            status=getattr(o, "status", "active"),
            quantum_risk_score=o.quantum_risk_score,
            user_count=users.get(o.id, 0),
            asset_count=assets.get(o.id, 0),
            scan_count=scans.get(o.id, 0),
            last_scan_at=last_scan.get(o.id),
            created_at=o.created_at,
        )
        for o in orgs
    ]


@router.patch("/orgs/{org_id}", response_model=OrgAdminOut)
async def update_org(
    org_id: uuid.UUID,
    body: OrgPatch,
    _op: Annotated[User, Depends(require_operator)],
    db: AsyncSession = Depends(get_db),
):
    org = await db.get(Organisation, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organisation not found")
    if body.plan is not None:
        if body.plan not in _VALID_PLANS:
            raise HTTPException(status_code=400, detail=f"plan must be one of {sorted(_VALID_PLANS)}")
        org.plan = body.plan
    if body.status is not None:
        if body.status not in _VALID_STATUS:
            raise HTTPException(status_code=400, detail=f"status must be one of {sorted(_VALID_STATUS)}")
        org.status = body.status
    await db.commit()
    await db.refresh(org)

    users, assets, scans, last_scan = await _counts(db)
    return OrgAdminOut(
        id=org.id, name=org.name, sector=org.sector, plan=org.plan,
        status=getattr(org, "status", "active"), quantum_risk_score=org.quantum_risk_score,
        user_count=users.get(org.id, 0), asset_count=assets.get(org.id, 0),
        scan_count=scans.get(org.id, 0), last_scan_at=last_scan.get(org.id),
        created_at=org.created_at,
    )


@router.get("/stats")
async def platform_stats(
    _op: Annotated[User, Depends(require_operator)],
    db: AsyncSession = Depends(get_db),
):
    async def _count(model):
        return (await db.execute(select(func.count()).select_from(model))).scalar() or 0

    orgs_by_plan = dict((await db.execute(
        select(Organisation.plan, func.count()).group_by(Organisation.plan)
    )).all())
    suspended = (await db.execute(
        select(func.count()).select_from(Organisation).where(Organisation.status == "suspended")
    )).scalar() or 0

    return {
        "total_orgs": await _count(Organisation),
        "total_users": await _count(User),
        "total_assets": await _count(Asset),
        "total_scans": await _count(Scan),
        "orgs_by_plan": orgs_by_plan,
        "suspended_orgs": suspended,
    }


# ── Blog / CMS (operator-authored) ────────────────────────────────────────────

class PostCreate(BaseModel):
    title: str
    body: str = ""
    excerpt: Optional[str] = None
    slug: Optional[str] = None
    tags: list[str] = []
    status: str = "draft"


class PostPatch(BaseModel):
    title: Optional[str] = None
    body: Optional[str] = None
    excerpt: Optional[str] = None
    tags: Optional[list[str]] = None
    status: Optional[str] = None


class PostOut(BaseModel):
    id: uuid.UUID
    slug: str
    title: str
    excerpt: Optional[str]
    body: str
    status: str
    tags: list
    author_email: Optional[str]
    published_at: Optional[datetime]
    created_at: datetime

    model_config = {"from_attributes": True}


@router.get("/posts", response_model=list[PostOut])
async def list_posts(
    _op: Annotated[User, Depends(require_operator)],
    db: AsyncSession = Depends(get_db),
):
    rows = (await db.execute(select(BlogPost).order_by(BlogPost.created_at.desc()))).scalars().all()
    return list(rows)


@router.post("/posts", response_model=PostOut)
async def create_post(
    body: PostCreate,
    op: Annotated[User, Depends(require_operator)],
    db: AsyncSession = Depends(get_db),
):
    if body.status not in _VALID_POST_STATUS:
        raise HTTPException(status_code=400, detail="status must be draft or published")
    slug = _slugify(body.slug or body.title)
    if (await db.execute(select(BlogPost).where(BlogPost.slug == slug))).scalar_one_or_none():
        slug = f"{slug}-{uuid.uuid4().hex[:6]}"

    post = BlogPost(
        slug=slug, title=body.title, body=body.body, excerpt=body.excerpt,
        tags=body.tags, status=body.status, author_email=op.email,
        published_at=datetime.utcnow() if body.status == "published" else None,
    )
    db.add(post)
    await db.commit()
    await db.refresh(post)
    return post


@router.patch("/posts/{post_id}", response_model=PostOut)
async def update_post(
    post_id: uuid.UUID,
    body: PostPatch,
    _op: Annotated[User, Depends(require_operator)],
    db: AsyncSession = Depends(get_db),
):
    post = await db.get(BlogPost, post_id)
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if body.title is not None:
        post.title = body.title
    if body.body is not None:
        post.body = body.body
    if body.excerpt is not None:
        post.excerpt = body.excerpt
    if body.tags is not None:
        post.tags = body.tags
    if body.status is not None:
        if body.status not in _VALID_POST_STATUS:
            raise HTTPException(status_code=400, detail="status must be draft or published")
        if body.status == "published" and post.published_at is None:
            post.published_at = datetime.utcnow()
        post.status = body.status
    await db.commit()
    await db.refresh(post)
    return post


@router.delete("/posts/{post_id}", status_code=204)
async def delete_post(
    post_id: uuid.UUID,
    _op: Annotated[User, Depends(require_operator)],
    db: AsyncSession = Depends(get_db),
):
    post = await db.get(BlogPost, post_id)
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    await db.delete(post)
    await db.commit()
