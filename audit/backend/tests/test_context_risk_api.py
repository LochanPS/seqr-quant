"""GET /api/v1/graph/risk — context-aware (risk v2) ranking of current crypto slots, org-scoped."""

import asyncio
import os
import uuid
from datetime import datetime

os.environ.setdefault("SECRET_KEY", "dev")
_DBFILE = "./_context_risk_test.db"
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_DBFILE}"

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session

import app.models  # noqa: F401
from app.database import Base, get_db
from app.main import app
from app.models.asset import Asset
from app.models.asset_edge import AssetEdge
from app.models.crypto_component import CryptoComponent
from app.security import get_current_user
from app.spine.ingest import project_component_state
from app.spine.sources import DiscoverySource, precedence_for

_engine = create_async_engine(os.environ["DATABASE_URL"])
_Sess = async_sessionmaker(_engine, class_=AsyncSession, expire_on_commit=False)

ORG_A, ORG_B = uuid.uuid4(), uuid.uuid4()


class _FakeUser:
    def __init__(self, org_id):
        self.org_id = org_id
        self.id = uuid.uuid4()
        self.email = "u@example.com"
        self.role = "admin"
        self.token_version = 0


def _obs(org, asset_id, loc, algo, fam, status, source=DiscoverySource.EXTERNAL_SCANNER):
    return CryptoComponent(org_id=org, scan_id=uuid.uuid4(), asset_id=asset_id, location_type=loc,
                           location_detail=loc, algorithm=algo, algorithm_family=fam,
                           quantum_status=status, source=source, precedence=precedence_for(source),
                           observed_at=datetime(2026, 1, 1))


def _seed_sync():
    eng = create_engine(f"sqlite:///{_DBFILE}")
    Base.metadata.create_all(eng)
    with Session(eng) as s:
        edge = Asset(org_id=ORG_A, type="domain", identifier="kyc.bank.example", name="edge",
                     provenance="user_declared", data_sensitivity="confidential")
        origin = Asset(org_id=ORG_A, type="origin", identifier="origin-kyc.bank.example", name="origin",
                       provenance="discovered", data_sensitivity="confidential")
        host = Asset(org_id=ORG_A, type="host", identifier="app01.internal", name="host",
                     provenance="discovered", data_sensitivity="internal")
        migrated = Asset(org_id=ORG_A, type="domain", identifier="www.bank.example", name="www",
                         provenance="user_declared", data_sensitivity="public")
        other = Asset(org_id=ORG_B, type="domain", identifier="secret.other.example", name="b",
                      provenance="user_declared", data_sensitivity="highly_confidential")
        s.add_all([edge, origin, host, migrated, other]); s.flush()
        s.add_all([
            _obs(ORG_A, edge.id, "tls_kex", "X25519", "ECC", "vulnerable"),
            _obs(ORG_A, edge.id, "tls_cert", "RSA-2048", "RSA", "vulnerable"),
            _obs(ORG_A, origin.id, "tls_kex", "X25519", "ECC", "vulnerable"),
            _obs(ORG_A, host.id, "tls_kex", "ECDHE", "ECC", "vulnerable", DiscoverySource.DISCOVERY_AGENT),
            _obs(ORG_A, migrated.id, "tls_kex", "X25519MLKEM768", "ML-KEM", "hybrid", DiscoverySource.ACTIVE_PROBE),
            _obs(ORG_B, other.id, "tls_kex", "X25519", "ECC", "vulnerable"),
        ])
        s.add(AssetEdge(org_id=ORG_A, src_asset_id=edge.id, dst_asset_id=origin.id, relation="origin_of",
                        discovered_by=DiscoverySource.EXTERNAL_SCANNER, confidence=0.6))
        s.commit()
        for org, a in ((ORG_A, edge), (ORG_A, origin), (ORG_A, host), (ORG_A, migrated), (ORG_B, other)):
            project_component_state(s, org, a.id)
        s.commit()
    eng.dispose()


async def _get_db_override():
    async with _Sess() as s:
        yield s


def setup_module(_):
    _seed_sync()
    app.dependency_overrides[get_db] = _get_db_override
    app.dependency_overrides[get_current_user] = lambda: _FakeUser(ORG_A)


def teardown_module(_):
    app.dependency_overrides.clear()
    asyncio.run(_engine.dispose())
    try:
        os.remove(_DBFILE)
    except OSError:
        pass


def _get():
    with TestClient(app) as c:
        r = c.get("/api/v1/graph/risk")
    assert r.status_code == 200, r.text
    return r.json()


def test_org_isolation():
    d = _get()
    ids = {c["file_path"] for c in d["components"]}
    assert "secret.other.example" not in ids
    assert ids >= {"kyc.bank.example", "origin-kyc.bank.example", "app01.internal", "www.bank.example"}


def test_ranked_and_explained():
    comps = _get()["components"]
    scores = [c["score"] for c in comps]
    assert scores == sorted(scores, reverse=True)
    assert all(c["reasons"] and c["factors"] for c in comps)


def test_context_changes_the_ranking():
    by = {(c["file_path"], c["slot_key"]): c for c in _get()["components"]}
    kex = by[("kyc.bank.example", "tls:kex")]
    cert = by[("kyc.bank.example", "tls:cert")]
    host = by[("app01.internal", "tls:kex")]
    hybrid = by[("www.bank.example", "tls:kex")]
    assert kex["hndl"] is True and kex["role"] == "key_exchange"
    assert cert["role"] == "signature" and cert["hndl"] is False and cert["score"] < kex["score"]
    assert host["exposure"] == "internal" and host["score"] < kex["score"]
    assert hybrid["score"] == 0 and hybrid["tier"] == "MONITOR"


def test_origin_bypass_is_called_out():
    by = {(c["file_path"], c["slot_key"]): c for c in _get()["components"]}
    origin = by[("origin-kyc.bank.example", "tls:kex")]
    assert any("route around edge" in f["reason"] for f in origin["factors"])
    assert origin["dependents"] >= 2


def test_summary_has_disclaimer():
    s = _get()["summary"]
    assert "not indicators of active data interception" in s["hndl_disclaimer"]
    assert sum(s["tiers"].values()) == s["findings"]
