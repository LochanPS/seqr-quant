"""CI-2: `seqr ci` → dashboard push endpoint (auth, feature flag, org scoping)."""
import pytest

from app.config import settings


@pytest.fixture(autouse=True)
def _enable_ingest():
    """Feature-flagged off by default; enable for these tests and restore after."""
    prev = settings.CI_INGEST_ENABLED
    settings.CI_INGEST_ENABLED = True
    yield
    settings.CI_INGEST_ENABLED = prev


def _payload(**over):
    body = {
        "repo": "acme/api",
        "pr_number": 42,
        "commit_sha": "deadbeef",
        "branch": "feature/pqc",
        "source": "github",
        "summary": {"critical": 1, "high": 0, "components_found": 1},
        "gate": {"should_fail": True, "drift_count": 1},
        "findings": [
            {"id": "py.jwt.rs256", "file": "src/auth.py", "line": 42,
             "algorithm": "RSA-SHA256", "severity": "critical"},
        ],
    }
    body.update(over)
    return body


async def _token(client):
    r = await client.post("/api/v1/auth/register", json={
        "email": "ci@acme.com", "password": "SecurePass123!",
        "name": "CI Bot", "org_name": "Acme",
    })
    assert r.status_code == 200
    return r.json()["access_token"]


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_push_and_list_and_detail(client):
    token = await _token(client)
    r = await client.post("/api/v1/ci/findings", json=_payload(), headers=_auth(token))
    assert r.status_code == 201, r.text
    created = r.json()
    assert created["repo"] == "acme/api"
    assert created["findings_count"] == 1
    assert created["summary"]["gate"]["drift_count"] == 1
    report_id = created["id"]

    lst = await client.get("/api/v1/ci/reports", headers=_auth(token))
    assert lst.status_code == 200
    assert any(row["id"] == report_id for row in lst.json())

    detail = await client.get(f"/api/v1/ci/reports/{report_id}", headers=_auth(token))
    assert detail.status_code == 200
    assert detail.json()["findings"][0]["file"] == "src/auth.py"


@pytest.mark.asyncio
async def test_requires_auth(client):
    r = await client.post("/api/v1/ci/findings", json=_payload())
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_feature_flag_off_returns_403(client):
    token = await _token(client)
    settings.CI_INGEST_ENABLED = False
    r = await client.post("/api/v1/ci/findings", json=_payload(), headers=_auth(token))
    assert r.status_code == 403
    settings.CI_INGEST_ENABLED = True


@pytest.mark.asyncio
async def test_org_scoping_hides_other_orgs_report(client):
    t1 = await _token(client)
    r = await client.post("/api/v1/ci/findings", json=_payload(), headers=_auth(t1))
    report_id = r.json()["id"]

    # A second org must not see or fetch org 1's report.
    r2 = await client.post("/api/v1/auth/register", json={
        "email": "other@beta.com", "password": "SecurePass123!",
        "name": "Other", "org_name": "Beta",
    })
    t2 = r2.json()["access_token"]

    lst = await client.get("/api/v1/ci/reports", headers=_auth(t2))
    assert lst.json() == []

    detail = await client.get(f"/api/v1/ci/reports/{report_id}", headers=_auth(t2))
    assert detail.status_code == 404  # 404-not-403 on cross-tenant id


@pytest.mark.asyncio
async def test_api_key_auth_accepted(client, db_session):
    """The CI use case authenticates with an sq_live_ API key, not a JWT."""
    import hashlib
    from app.models.api_key import APIKey
    from app.models.user import User
    from sqlalchemy import select

    token = await _token(client)  # registers the org + user
    user = (await db_session.execute(select(User).where(User.email == "ci@acme.com"))).scalar_one()

    raw = "sq_live_citestkey1234567890"
    db_session.add(APIKey(
        org_id=user.org_id, user_id=user.id, name="ci", key_prefix="sq_live_ci",
        key_hash=hashlib.sha256(raw.encode()).hexdigest(),
    ))
    await db_session.commit()

    r = await client.post("/api/v1/ci/findings", json=_payload(), headers=_auth(raw))
    assert r.status_code == 201, r.text
