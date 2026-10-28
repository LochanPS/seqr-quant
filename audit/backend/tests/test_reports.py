import uuid
from datetime import datetime, timezone

import pytest

from app.models.crypto_component import CryptoComponent
from app.models.scan import Scan


async def _get_token(client) -> str:
    r = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "reports_user@testcorp.com",
            "password": "SecurePass123!",
            "name": "Reports User",
            "org_name": "Reports Corp",
        },
    )
    assert r.status_code == 200
    return r.json()["access_token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


async def _seed(client, db_session, token: str) -> None:
    org_r = await client.get("/api/v1/org", headers=_auth(token))
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
        ),
    ]
    for c in comps:
        db_session.add(c)
    await db_session.commit()


@pytest.mark.asyncio
async def test_generate_executive_summary(client, db_session):
    token = await _get_token(client)
    await _seed(client, db_session, token)

    r = await client.post(
        "/api/v1/reports/generate",
        headers=_auth(token),
        json={"type": "executive_summary"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "complete"
    assert data["type"] == "executive_summary"
    assert data["storage_path"] is not None
    assert data["component_count"] == 3


@pytest.mark.asyncio
async def test_generate_technical_audit(client, db_session):
    token = await _get_token(client)
    await _seed(client, db_session, token)

    r = await client.post(
        "/api/v1/reports/generate",
        headers=_auth(token),
        json={"type": "technical_audit"},
    )
    assert r.status_code == 200
    assert r.json()["status"] == "complete"


@pytest.mark.asyncio
async def test_list_reports(client, db_session):
    token = await _get_token(client)
    await _seed(client, db_session, token)

    r = await client.get("/api/v1/reports", headers=_auth(token))
    assert r.status_code == 200
    assert isinstance(r.json(), list)


@pytest.mark.asyncio
async def test_download_report_returns_pdf_bytes(client, db_session):
    token = await _get_token(client)
    await _seed(client, db_session, token)

    gen = await client.post(
        "/api/v1/reports/generate",
        headers=_auth(token),
        json={"type": "executive_summary"},
    )
    assert gen.status_code == 200
    report_id = gen.json()["id"]

    r = await client.get(
        f"/api/v1/reports/{report_id}/download",
        headers=_auth(token),
    )
    assert r.status_code == 200
    assert len(r.content) > 0
    # ReportLab PDFs start with %PDF
    assert r.content[:4] == b"%PDF"


@pytest.mark.asyncio
async def test_report_count_increases(client, db_session):
    token = await _get_token(client)
    await _seed(client, db_session, token)

    before = len((await client.get("/api/v1/reports", headers=_auth(token))).json())

    await client.post(
        "/api/v1/reports/generate",
        headers=_auth(token),
        json={"type": "technical_audit"},
    )

    after = len((await client.get("/api/v1/reports", headers=_auth(token))).json())
    assert after == before + 1


@pytest.mark.asyncio
async def test_invalid_report_type_rejected(client, db_session):
    token = await _get_token(client)
    r = await client.post(
        "/api/v1/reports/generate",
        headers=_auth(token),
        json={"type": "bogus_type"},
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_get_report_metadata(client, db_session):
    token = await _get_token(client)
    await _seed(client, db_session, token)

    gen = await client.post(
        "/api/v1/reports/generate",
        headers=_auth(token),
        json={"type": "executive_summary"},
    )
    report_id = gen.json()["id"]

    r = await client.get(f"/api/v1/reports/{report_id}", headers=_auth(token))
    assert r.status_code == 200
    data = r.json()
    assert data["id"] == report_id
    assert data["type"] == "executive_summary"
    assert data["status"] == "complete"
