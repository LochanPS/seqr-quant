import uuid
from datetime import datetime, timezone

import pytest

from app.models.crypto_component import CryptoComponent
from app.models.scan import Scan


async def _get_token(client) -> str:
    r = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "risk_user@testcorp.com",
            "password": "SecurePass123!",
            "name": "Risk User",
            "org_name": "Risk Corp",
        },
    )
    assert r.status_code == 200
    return r.json()["access_token"]


async def _seed(client, db_session, token: str) -> None:
    org_r = await client.get("/api/v1/org", headers={"Authorization": f"Bearer {token}"})
    org_id = uuid.UUID(org_r.json()["id"])

    scan = Scan(
        org_id=org_id,
        type="network",
        status="complete",
        trigger="manual",
        completed_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    db_session.add(scan)
    await db_session.flush()

    comps = [
        CryptoComponent(
            org_id=org_id,
            scan_id=scan.id,
            location_type="tls_cert",
            location_detail="api.example.com:443",
            algorithm="RSA-2048",
            algorithm_family="RSA",
            quantum_status="vulnerable",
            pqc_migration_priority=8.0,
            estimated_hndl_exposure="high",
            threat_timeline="IMMEDIATE",
            migration_status="open",
            deployment_level=3,
            crypto_agility_score=2.0,
        ),
        CryptoComponent(
            org_id=org_id,
            scan_id=scan.id,
            location_type="tls_cert",
            location_detail="cdn.example.com:443",
            algorithm="ECDSA-256",
            algorithm_family="ECC",
            quantum_status="vulnerable",
            pqc_migration_priority=6.0,
            estimated_hndl_exposure="medium",
            threat_timeline="URGENT",
            migration_status="open",
            deployment_level=4,
            crypto_agility_score=3.0,
        ),
        CryptoComponent(
            org_id=org_id,
            scan_id=scan.id,
            location_type="tls_cert",
            location_detail="secure.example.com:443",
            algorithm="ML-KEM-768",
            algorithm_family="ML-KEM",
            quantum_status="safe",
            pqc_migration_priority=1.0,
            estimated_hndl_exposure="low",
            threat_timeline="ROADMAP",
            migration_status="done",
            deployment_level=4,
            crypto_agility_score=9.5,
        ),
    ]
    for c in comps:
        db_session.add(c)
    await db_session.commit()


async def test_risk_score_returns_0_100(client, db_session):
    token = await _get_token(client)
    await _seed(client, db_session, token)

    r = await client.get("/api/v1/risk/score", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    data = r.json()
    score = data["score"]
    assert 0 <= score <= 100
    assert "label" in data
    assert data["label"] in ("low", "medium", "high", "critical")
    assert data["vulnerable_count"] == 2
    assert data["total_components"] == 3


async def test_compliance_has_all_frameworks(client, db_session):
    token = await _get_token(client)
    await _seed(client, db_session, token)

    r = await client.get("/api/v1/risk/compliance", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    d = r.json()
    for fw in ["PCI_DSS_12_3_3", "NIST_FIPS", "DST_TASK_FORCE_2026", "RBI_IT_FRAMEWORK", "CERT_IN"]:
        assert fw in d
        assert "status" in d[fw]
        assert "message" in d[fw]


async def test_compliance_no_cnsa(client, db_session):
    token = await _get_token(client)
    await _seed(client, db_session, token)

    r = await client.get("/api/v1/risk/compliance", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert "CNSA" not in str(r.json())


async def test_roadmap_has_all_timelines(client, db_session):
    token = await _get_token(client)
    await _seed(client, db_session, token)

    r = await client.get("/api/v1/risk/roadmap", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    d = r.json()
    for tl in ["IMMEDIATE", "URGENT", "PLANNED", "ROADMAP"]:
        assert tl in d
        assert "label" in d[tl]
        assert "components" in d[tl]
    assert d["IMMEDIATE"]["count"] == 1
    assert d["URGENT"]["count"] == 1
    assert d["ROADMAP"]["count"] == 1


async def test_hndl_endpoint(client, db_session):
    token = await _get_token(client)
    await _seed(client, db_session, token)

    r = await client.get("/api/v1/risk/hndl", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["estimated_hndl_exposure"] == "high"
