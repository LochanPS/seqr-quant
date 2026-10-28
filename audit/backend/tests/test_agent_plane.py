"""Discovery-agent plane (PRD 15): ingest write-path + credential management.

Two layers, matching how the rest of the spine is tested:
  * unit — ingest_agent_batch / agent_status against a self-contained sync SQLite session
    (source precedence, idempotent retries, quantum-status inference, coverage).
  * router — auth, scope enforcement, feature flag, admin gate, and tenant isolation through
    the async client. The ingest write runs on SyncSessionLocal, so the one end-to-end test
    points that at an isolated in-memory sync engine.
"""
import hashlib
import os
import uuid
from datetime import datetime

os.environ.setdefault("SECRET_KEY", "dev")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

import app.database as database
import app.models  # noqa: F401 — register models
from app.config import settings
from app.database import Base
from app.models.api_key import APIKey
from app.models.component_state import ComponentState
from app.models.crypto_component import CryptoComponent
from app.spine.agent_ingest import agent_status, ingest_agent_batch
from app.spine.ingest import project_component_state, resolve_asset
from app.spine.sources import DiscoverySource, precedence_for


# ============================================================ unit: ingest logic
def _session() -> Session:
    eng = create_engine("sqlite://")
    Base.metadata.create_all(eng)
    return Session(eng)


def _obs(**over):
    o = {
        "asset_key": "lb-01.internal",
        "asset_key_type": "host",
        "asset_type": "load_balancer",
        "location_type": "tls_kex",
        "location_detail": "lb-01.internal:443 (kex)",
        "algorithm": "X25519",
        "algorithm_family": "ECC",
        "quantum_status": "vulnerable",
        "confidence": "high",
        "observed_at": datetime(2026, 9, 15, 10, 0, 0),
    }
    o.update(over)
    return o


def test_ingest_creates_assets_and_agent_observations():
    s = _session()
    org = uuid.uuid4()
    res = ingest_agent_batch(s, org, "agent:sq_live_x", [
        _obs(asset_key="lb-01.internal"),
        _obs(asset_key="ca-root", asset_key_type="pki", asset_type="internal_ca",
             location_type="tls_cert", algorithm="RSA-2048", algorithm_family="RSA",
             quantum_status="vulnerable"),
    ], agent_name="dc-mumbai-agent")

    assert res["ingested"] == 2
    assert res["assets_touched"] == 2
    assert res["skipped_duplicates"] == 0

    rows = s.query(CryptoComponent).all()
    assert len(rows) == 2
    assert all(r.source == DiscoverySource.DISCOVERY_AGENT.value for r in rows)
    assert all(r.precedence == precedence_for(DiscoverySource.DISCOVERY_AGENT) for r in rows)
    # current state projected for every touched slot
    assert s.query(ComponentState).count() == 2


def test_ingest_is_idempotent_on_retry():
    s = _session()
    org = uuid.uuid4()
    batch = [_obs()]
    first = ingest_agent_batch(s, org, "agent:x", batch)
    second = ingest_agent_batch(s, org, "agent:x", batch)  # exact retry

    assert first["ingested"] == 1
    assert second["ingested"] == 0
    assert second["skipped_duplicates"] == 1
    # the retry created no duplicate observation
    assert s.query(CryptoComponent).count() == 1


def test_agent_source_beats_external_scanner_in_projection():
    s = _session()
    org = uuid.uuid4()
    # An outside-in scanner already saw a classical kex on this asset.
    asset_id = resolve_asset(s, org, "host", "lb-01.internal", asset_type="load_balancer")
    s.add(CryptoComponent(
        org_id=org, scan_id=uuid.uuid4(), asset_id=asset_id, location_type="tls_kex",
        location_detail="edge", algorithm="X25519", algorithm_family="ECC",
        quantum_status="vulnerable", source=DiscoverySource.EXTERNAL_SCANNER.value,
        precedence=precedence_for(DiscoverySource.EXTERNAL_SCANNER),
        observed_at=datetime(2026, 1, 1),
    ))
    s.commit()
    project_component_state(s, org, asset_id)
    s.commit()

    # The agent, inside the perimeter, reports the real negotiated hybrid group.
    ingest_agent_batch(s, org, "agent:x", [_obs(
        asset_key="lb-01.internal", algorithm="X25519MLKEM768",
        algorithm_family="ML-KEM", quantum_status="hybrid",
        observed_at=datetime(2026, 9, 15),
    )])

    cs = (s.query(ComponentState)
          .filter(ComponentState.asset_id == asset_id, ComponentState.slot_key == "tls:kex")
          .one())
    winner = s.get(CryptoComponent, cs.winning_observation_id)
    assert winner.source == DiscoverySource.DISCOVERY_AGENT.value
    assert winner.algorithm == "X25519MLKEM768"


def test_quantum_status_inferred_when_omitted():
    s = _session()
    org = uuid.uuid4()
    ingest_agent_batch(s, org, "agent:x", [
        _obs(asset_key="a", algorithm="RSA-2048", algorithm_family=None, quantum_status=None),
        _obs(asset_key="b", algorithm="ML-KEM-768", algorithm_family=None, quantum_status=None,
             location_type="tls_cert"),
        _obs(asset_key="c", algorithm="X25519MLKEM768", algorithm_family=None, quantum_status=None,
             location_type="tls_kex"),
    ])
    by_algo = {r.algorithm: r for r in s.query(CryptoComponent).all()}
    assert by_algo["RSA-2048"].quantum_status == "vulnerable"
    assert by_algo["ML-KEM-768"].quantum_status == "safe"
    assert by_algo["X25519MLKEM768"].quantum_status == "hybrid"


def test_agent_status_reports_coverage():
    s = _session()
    org = uuid.uuid4()
    ingest_agent_batch(s, org, "agent:x", [
        _obs(asset_key="a", location_type="tls_cert"),
        _obs(asset_key="b", location_type="ssh_hostkey", algorithm="ssh-rsa"),
    ])
    st = agent_status(s, org)
    assert st["observations"] == 2
    assert st["assets_covered"] == 2
    assert set(st["plugin_coverage"]) == {"tls_cert", "ssh_hostkey"}
    assert st["last_observed_at"] is not None


# ============================================================ router: auth & mgmt
def _auth(token):
    return {"Authorization": f"Bearer {token}"}


async def _register(client, email="admin@acme.com", org="Acme"):
    r = await client.post("/api/v1/auth/register", json={
        "email": email, "password": "SecurePass123!", "name": "Admin", "org_name": org,
    })
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


async def _mint_agent(client, token, name="dc-mumbai"):
    r = await client.post("/api/v1/agent/credentials", json={"name": name}, headers=_auth(token))
    assert r.status_code == 201, r.text
    return r.json()


@pytest.fixture
def sync_db(monkeypatch):
    """Point the ingest write-path (SyncSessionLocal) at an isolated in-memory sync engine."""
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    monkeypatch.setattr(database, "SyncSessionLocal", sessionmaker(bind=eng, expire_on_commit=False))
    return eng


@pytest.fixture(autouse=True)
def _restore_flag():
    prev = settings.AGENT_INGEST_ENABLED
    yield
    settings.AGENT_INGEST_ENABLED = prev


@pytest.mark.asyncio
async def test_mint_list_and_revoke_credential(client):
    token = await _register(client)
    created = await _mint_agent(client, token)
    assert created["key"].startswith("sq_live_")
    assert created["key_prefix"] == created["key"][:8]

    lst = await client.get("/api/v1/agent/credentials", headers=_auth(token))
    assert lst.status_code == 200
    assert any(row["id"] == created["id"] for row in lst.json())

    rev = await client.delete(f"/api/v1/agent/credentials/{created['id']}", headers=_auth(token))
    assert rev.status_code == 204
    lst2 = await client.get("/api/v1/agent/credentials", headers=_auth(token))
    assert all(row["id"] != created["id"] for row in lst2.json())


@pytest.mark.asyncio
async def test_ingest_requires_agent_scope_not_jwt(client):
    """A user JWT is not an agent credential — agents authenticate with an sq_live_ key."""
    token = await _register(client)
    settings.AGENT_INGEST_ENABLED = True
    r = await client.post("/api/v1/agent/observations",
                          json={"observations": [_json_obs()]}, headers=_auth(token))
    assert r.status_code == 401  # bearer is a JWT, not an sq_live_ key


@pytest.mark.asyncio
async def test_ingest_rejects_key_without_agent_scope(client, db_session):
    from app.models.user import User
    from sqlalchemy import select

    token = await _register(client)
    settings.AGENT_INGEST_ENABLED = True
    user = (await db_session.execute(select(User).where(User.email == "admin@acme.com"))).scalar_one()
    raw = "sq_live_plainkey1234567890"
    db_session.add(APIKey(org_id=user.org_id, user_id=user.id, name="plain", key_prefix="sq_live_p",
                          key_hash=hashlib.sha256(raw.encode()).hexdigest(), scopes=[]))
    await db_session.commit()

    r = await client.post("/api/v1/agent/observations",
                          json={"observations": [_json_obs()]}, headers=_auth(raw))
    assert r.status_code == 403  # lacks the 'agent' scope


@pytest.mark.asyncio
async def test_ingest_feature_flag_off_returns_403(client):
    token = await _register(client)
    cred = await _mint_agent(client, token)
    settings.AGENT_INGEST_ENABLED = False
    r = await client.post("/api/v1/agent/observations",
                          json={"observations": [_json_obs()]}, headers=_auth(cred["key"]))
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_ingest_and_status_end_to_end(client, sync_db):
    token = await _register(client)
    cred = await _mint_agent(client, token)
    settings.AGENT_INGEST_ENABLED = True

    key = str(uuid.uuid4())  # unique asset so the count is deterministic
    r = await client.post("/api/v1/agent/observations", headers=_auth(cred["key"]), json={
        "agent": "dc-mumbai-agent",
        "observations": [_json_obs(asset_key=key), _json_obs(asset_key=key + "-ca",
                                                              location_type="tls_cert",
                                                              algorithm="RSA-2048")],
    })
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["ingested"] == 2
    assert body["assets_touched"] == 2

    st = await client.get("/api/v1/agent/status", headers=_auth(cred["key"]))
    assert st.status_code == 200
    assert st.json()["observations"] >= 2


@pytest.mark.asyncio
async def test_coverage_endpoint_user_authed(client, sync_db):
    """The dashboard admin (JWT, no agent key) reads org agent coverage via /agent/coverage."""
    token = await _register(client)
    cred = await _mint_agent(client, token)
    settings.AGENT_INGEST_ENABLED = True

    # Empty before any upload.
    empty = await client.get("/api/v1/agent/coverage", headers=_auth(token))
    assert empty.status_code == 200
    assert empty.json()["observations"] == 0

    await client.post("/api/v1/agent/observations", headers=_auth(cred["key"]), json={
        "observations": [_json_obs(asset_key=str(uuid.uuid4()))],
    })

    cov = await client.get("/api/v1/agent/coverage", headers=_auth(token))
    assert cov.status_code == 200
    assert cov.json()["observations"] >= 1
    assert "tls_kex" in cov.json()["plugin_coverage"]


@pytest.mark.asyncio
async def test_credential_tenant_isolation(client):
    ta = await _register(client, email="a@acme.com", org="Acme")
    cred = await _mint_agent(client, ta)
    tb = await _register(client, email="b@beta.com", org="Beta")
    # Org B must not revoke org A's credential — 404 (not 403) on a cross-tenant id.
    r = await client.delete(f"/api/v1/agent/credentials/{cred['id']}", headers=_auth(tb))
    assert r.status_code == 404


def _json_obs(**over):
    o = {
        "asset_key": "lb-01.internal",
        "asset_type": "load_balancer",
        "location_type": "tls_kex",
        "location_detail": "lb-01.internal:443",
        "algorithm": "X25519",
        "algorithm_family": "ECC",
        "quantum_status": "vulnerable",
        "observed_at": "2026-09-15T10:00:00",
    }
    o.update(over)
    return o


# ==================================================== signed uploads + air-gap import
import base64  # noqa: E402

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding, PublicFormat,
)

from app.spine.agent_sig import canonical_bytes  # noqa: E402


def _keypair():
    """Return (private_key_obj, public_key_pem_str)."""
    priv = Ed25519PrivateKey.generate()
    pem = priv.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return priv, pem


def _sign(priv, observations) -> str:
    return base64.b64encode(priv.sign(canonical_bytes(observations))).decode()


async def _set_pubkey(db_session, org_id, key_prefix, pem):
    """Bind a public key to the org's agent credential (used by air-gap import tests)."""
    from sqlalchemy import select as _select
    row = (await db_session.execute(
        _select(APIKey).where(APIKey.org_id == org_id, APIKey.key_prefix == key_prefix)
    )).scalars().first()
    row.agent_public_key = pem
    await db_session.commit()


@pytest.mark.asyncio
async def test_tofu_register_then_signed_upload_accepted(client, sync_db):
    token = await _register(client)
    cred = await _mint_agent(client, token)
    settings.AGENT_INGEST_ENABLED = True
    priv, pem = _keypair()

    key = str(uuid.uuid4())
    obs = [_json_obs(asset_key=key)]

    # 1) First upload enrols the key (TOFU) — no signature yet.
    r1 = await client.post("/api/v1/agent/observations", headers={
        **_auth(cred["key"]), "X-Agent-Public-Key": pem,
    }, json={"observations": obs})
    assert r1.status_code == 201, r1.text

    # 2) Now the credential is key-bound; a correctly signed batch is accepted.
    obs2 = [_json_obs(asset_key=key + "-2")]
    r2 = await client.post("/api/v1/agent/observations", headers={
        **_auth(cred["key"]), "X-Agent-Signature": _sign(priv, obs2),
    }, json={"observations": obs2})
    assert r2.status_code == 201, r2.text
    assert r2.json()["ingested"] == 1


@pytest.mark.asyncio
async def test_key_bound_credential_rejects_unsigned_post(client, sync_db):
    token = await _register(client)
    cred = await _mint_agent(client, token)
    settings.AGENT_INGEST_ENABLED = True
    _, pem = _keypair()

    obs = [_json_obs(asset_key=str(uuid.uuid4()))]
    # Enrol the key.
    r1 = await client.post("/api/v1/agent/observations", headers={
        **_auth(cred["key"]), "X-Agent-Public-Key": pem,
    }, json={"observations": obs})
    assert r1.status_code == 201, r1.text

    # An unsigned upload is now refused.
    r2 = await client.post("/api/v1/agent/observations",
                           headers=_auth(cred["key"]), json={"observations": obs})
    assert r2.status_code == 401


@pytest.mark.asyncio
async def test_tampered_signed_upload_rejected(client, sync_db):
    token = await _register(client)
    cred = await _mint_agent(client, token)
    settings.AGENT_INGEST_ENABLED = True
    priv, pem = _keypair()

    obs = [_json_obs(asset_key=str(uuid.uuid4()))]
    r1 = await client.post("/api/v1/agent/observations", headers={
        **_auth(cred["key"]), "X-Agent-Public-Key": pem,
    }, json={"observations": obs})
    assert r1.status_code == 201, r1.text

    # Sign one batch but send a different (tampered) one.
    signed = [_json_obs(asset_key="original")]
    tampered = [_json_obs(asset_key="tampered")]
    r2 = await client.post("/api/v1/agent/observations", headers={
        **_auth(cred["key"]), "X-Agent-Signature": _sign(priv, signed),
    }, json={"observations": tampered})
    assert r2.status_code == 401


@pytest.mark.asyncio
async def test_airgap_import_round_trips_and_is_idempotent(client, db_session, sync_db):
    token = await _register(client)
    cred = await _mint_agent(client, token)
    priv, pem = _keypair()

    from app.models.user import User
    from sqlalchemy import select
    user = (await db_session.execute(select(User).where(User.email == "admin@acme.com"))).scalar_one()
    await _set_pubkey(db_session, user.org_id, cred["key_prefix"], pem)

    obs = [_json_obs(asset_key=str(uuid.uuid4())),
           _json_obs(asset_key=str(uuid.uuid4()), location_type="tls_cert", algorithm="RSA-2048")]
    envelope = {
        "version": 1, "agent": "dc-mumbai-agent", "key_prefix": cred["key_prefix"],
        "signed_at": "2026-09-15T10:00:00", "observations": obs, "signature": _sign(priv, obs),
    }

    r1 = await client.post("/api/v1/agent/import", headers=_auth(token), json=envelope)
    assert r1.status_code == 201, r1.text
    assert r1.json()["ingested"] == 2

    # Re-import the same envelope: dedupe makes it a no-op.
    r2 = await client.post("/api/v1/agent/import", headers=_auth(token), json=envelope)
    assert r2.status_code == 201, r2.text
    assert r2.json()["ingested"] == 0
    assert r2.json()["skipped_duplicates"] == 2


@pytest.mark.asyncio
async def test_airgap_import_unknown_key_prefix_404(client, db_session, sync_db):
    token = await _register(client)
    await _mint_agent(client, token)  # exists but not the prefix we send
    priv, _ = _keypair()
    obs = [_json_obs(asset_key=str(uuid.uuid4()))]
    envelope = {
        "version": 1, "key_prefix": "sq_nope_", "observations": obs, "signature": _sign(priv, obs),
    }
    r = await client.post("/api/v1/agent/import", headers=_auth(token), json=envelope)
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_airgap_import_tampered_signature_400(client, db_session, sync_db):
    token = await _register(client)
    cred = await _mint_agent(client, token)
    priv, pem = _keypair()

    from app.models.user import User
    from sqlalchemy import select
    user = (await db_session.execute(select(User).where(User.email == "admin@acme.com"))).scalar_one()
    await _set_pubkey(db_session, user.org_id, cred["key_prefix"], pem)

    signed = [_json_obs(asset_key="signed")]
    tampered = [_json_obs(asset_key="tampered")]
    envelope = {
        "version": 1, "key_prefix": cred["key_prefix"],
        "observations": tampered, "signature": _sign(priv, signed),
    }
    r = await client.post("/api/v1/agent/import", headers=_auth(token), json=envelope)
    assert r.status_code == 400
