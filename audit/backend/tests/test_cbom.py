import uuid

import pytest

from app.models.crypto_component import CryptoComponent
from app.models.scan import Scan


async def _get_token(client) -> str:
    r = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "cbom_user@testcorp.com",
            "password": "SecurePass123!",
            "name": "CBOM User",
            "org_name": "CBOM Corp",
        },
    )
    assert r.status_code == 200
    return r.json()["access_token"]


async def _seed_components(client, db_session, token: str) -> None:
    org_r = await client.get("/api/v1/org", headers={"Authorization": f"Bearer {token}"})
    org_id = uuid.UUID(org_r.json()["id"])

    scan = Scan(org_id=org_id, type="network", status="complete", trigger="manual")
    db_session.add(scan)
    await db_session.flush()

    comps = [
        CryptoComponent(
            org_id=org_id,
            scan_id=scan.id,
            location_type="tls_cert",
            location_detail="example.com:443",
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
            location_detail="safe.example.com:443",
            algorithm="ML-DSA-65",
            algorithm_family="ML-DSA",
            quantum_status="safe",
            pqc_migration_priority=1.0,
            estimated_hndl_exposure="low",
            threat_timeline="ROADMAP",
            migration_status="done",
            deployment_level=4,
            crypto_agility_score=9.0,
        ),
    ]
    for c in comps:
        db_session.add(c)
    await db_session.commit()


async def test_cbom_list_returns_components(client, db_session):
    token = await _get_token(client)
    await _seed_components(client, db_session, token)

    r = await client.get("/api/v1/cbom", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    data = r.json()
    assert "items" in data
    assert "total" in data
    assert data["total"] == 2
    assert len(data["items"]) == 2


async def test_cbom_summary_has_required_fields(client, db_session):
    token = await _get_token(client)
    await _seed_components(client, db_session, token)

    r = await client.get("/api/v1/cbom/summary", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    d = r.json()
    assert "total_components" in d
    assert "vulnerable" in d
    assert "by_threat_timeline" in d
    assert d["total_components"] == 2
    assert d["vulnerable"] == 1
    assert d["safe"] == 1


async def test_cbom_export_json(client, db_session):
    token = await _get_token(client)
    await _seed_components(client, db_session, token)

    r = await client.get("/api/v1/cbom/export?format=json", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/json"
    data = r.json()
    assert isinstance(data, list)
    assert len(data) == 2


async def test_cbom_export_cyclonedx(client, db_session):
    token = await _get_token(client)
    await _seed_components(client, db_session, token)

    r = await client.get(
        "/api/v1/cbom/export?format=cyclonedx",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["bomFormat"] == "CycloneDX"
    assert data["specVersion"] == "1.6"
    assert "components" in data
    assert len(data["components"]) == 2


async def test_cbom_filter_by_quantum_status(client, db_session):
    token = await _get_token(client)
    await _seed_components(client, db_session, token)

    r = await client.get(
        "/api/v1/cbom?quantum_status=vulnerable",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["total"] == 1
    for item in data["items"]:
        assert item["quantum_status"] == "vulnerable"
