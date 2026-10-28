"""Append-only audit-log tests (A5).

Verifies that mutating requests write audit events, that the log is org-scoped, that
reads are permission-gated, and that filters work. Read access is covered further in
test_rbac.py (auditor yes, viewer no).
"""
import pytest


async def _register(client, email, org):
    r = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "SecurePass123!", "name": "T", "org_name": org},
    )
    assert r.status_code == 200
    return r.json()


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_mutation_writes_audit_event(client):
    admin = await _register(client, "admin@corp.com", "Corp")
    tok = admin["access_token"]

    # a mutating call
    r = await client.post(
        "/api/v1/assets",
        json={"type": "domain", "identifier": "example.com"},
        headers=_auth(tok),
    )
    assert r.status_code == 200
    asset_id = r.json()["id"]

    events = (await client.get("/api/v1/audit", headers=_auth(tok))).json()
    actions = [e["action"] for e in events]
    # registration + the asset creation are both captured
    assert "auth.register" in actions
    assert any(e["method"] == "POST" and e["path"] == "/api/v1/assets" for e in events)

    # the asset-create event carries route template + target id
    create = next(e for e in events if e["path"] == "/api/v1/assets" and e["method"] == "POST")
    assert create["action"] == "POST /api/v1/assets"
    assert create["status_code"] == 200
    assert create["actor"] == admin["user"]["id"]

    # delete is a mutation too → audited with the target id
    await client.delete(f"/api/v1/assets/{asset_id}", headers=_auth(tok))
    events = (await client.get("/api/v1/audit", headers=_auth(tok))).json()
    delete = next((e for e in events if e["method"] == "DELETE"), None)
    assert delete is not None
    assert delete["target"] == asset_id


@pytest.mark.asyncio
async def test_reads_are_not_audited(client):
    admin = await _register(client, "admin@corp.com", "Corp")
    tok = admin["access_token"]
    # several GETs
    for _ in range(3):
        await client.get("/api/v1/assets", headers=_auth(tok))
    events = (await client.get("/api/v1/audit", headers=_auth(tok))).json()
    assert all(e["method"] != "GET" for e in events)


@pytest.mark.asyncio
async def test_audit_is_org_scoped(client):
    a = await _register(client, "a@one.com", "OrgOne")
    b = await _register(client, "b@two.com", "OrgTwo")

    # OrgOne mutates
    await client.post(
        "/api/v1/assets",
        json={"type": "domain", "identifier": "one.example"},
        headers=_auth(a["access_token"]),
    )

    a_events = (await client.get("/api/v1/audit", headers=_auth(a["access_token"]))).json()
    b_events = (await client.get("/api/v1/audit", headers=_auth(b["access_token"]))).json()

    # OrgTwo never sees OrgOne's asset creation
    assert any(e["path"] == "/api/v1/assets" and e["method"] == "POST" for e in a_events)
    assert all(e["path"] != "/api/v1/assets" for e in b_events)
    # every row OrgTwo sees belongs to OrgTwo
    assert {e["org_id"] for e in b_events} <= {b["org"]["id"]}


@pytest.mark.asyncio
async def test_audit_filters(client):
    admin = await _register(client, "admin@corp.com", "Corp")
    tok = admin["access_token"]
    await client.post(
        "/api/v1/assets",
        json={"type": "domain", "identifier": "example.com"},
        headers=_auth(tok),
    )

    # action substring filter
    r = await client.get("/api/v1/audit", params={"action": "register"}, headers=_auth(tok))
    assert r.status_code == 200
    assert all("register" in e["action"] for e in r.json())
    assert len(r.json()) >= 1

    # actor filter
    r = await client.get("/api/v1/audit", params={"actor": admin["user"]["id"]}, headers=_auth(tok))
    assert all(e["actor"] == admin["user"]["id"] for e in r.json())
