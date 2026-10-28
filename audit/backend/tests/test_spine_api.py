"""Spine REST API — org isolation (PRD 13, Phase 1.5)."""

import asyncio
import os
import uuid

os.environ.setdefault("SECRET_KEY", "dev")
_DBFILE = "./_spine_api_test.db"
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_DBFILE}"

from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import app.models  # noqa: F401
from app.database import Base, get_db
from app.main import app
from app.models.asset import Asset
from app.security import get_current_user

_engine = create_async_engine(os.environ["DATABASE_URL"])
_Sess = async_sessionmaker(_engine, class_=AsyncSession, expire_on_commit=False)

ORG_A, ORG_B = uuid.uuid4(), uuid.uuid4()
A_ASSET, B_ASSET = uuid.uuid4(), uuid.uuid4()


class _FakeUser:
    def __init__(self, org_id):
        self.org_id = org_id
        self.id = uuid.uuid4()
        self.email = "u@example.com"
        self.role = "admin"
        self.token_version = 0


async def _seed():
    async with _engine.begin() as c:
        await c.run_sync(Base.metadata.create_all)
    async with _Sess() as s:
        s.add(Asset(id=A_ASSET, org_id=ORG_A, type="domain", identifier="a.in", name="a", provenance="user_declared"))
        s.add(Asset(id=B_ASSET, org_id=ORG_B, type="domain", identifier="b.in", name="b", provenance="user_declared"))
        await s.commit()


async def _get_db_override():
    async with _Sess() as s:
        yield s


def setup_module(_):
    asyncio.run(_seed())
    app.dependency_overrides[get_db] = _get_db_override
    app.dependency_overrides[get_current_user] = lambda: _FakeUser(ORG_A)


def teardown_module(_):
    app.dependency_overrides.clear()
    asyncio.run(_engine.dispose())
    try:
        os.remove(_DBFILE)
    except OSError:
        pass


client = TestClient(app)


def test_list_assets_is_org_scoped():
    r = client.get("/api/v1/graph/assets")
    assert r.status_code == 200
    ids = {a["id"] for a in r.json()}
    assert str(A_ASSET) in ids
    assert str(B_ASSET) not in ids, "must not see another org's asset"


def test_cross_tenant_asset_returns_404_not_403():
    assert client.get(f"/api/v1/graph/assets/{A_ASSET}").status_code == 200
    assert client.get(f"/api/v1/graph/assets/{B_ASSET}").status_code == 404
