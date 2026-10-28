"""Tests for the platform operator console."""
from app.config import settings


async def _register(client, email, org="Corp"):
    r = await client.post("/api/v1/auth/register", json={
        "email": email, "password": "Pass123!", "name": "U", "org_name": org,
    })
    return r.json()


def _auth(tok):
    return {"Authorization": f"Bearer {tok}"}


async def test_non_operator_forbidden(client):
    u = await _register(client, "normal@test.com")
    r = await client.get("/api/v1/admin/orgs", headers=_auth(u["access_token"]))
    assert r.status_code == 403


async def test_operator_lists_orgs_with_usage(client, monkeypatch):
    monkeypatch.setattr(settings, "OPERATOR_EMAILS", "op@test.com")
    op = await _register(client, "op@test.com", "Operator Org")
    await _register(client, "customer@test.com", "Customer Org")

    r = await client.get("/api/v1/admin/orgs", headers=_auth(op["access_token"]))
    assert r.status_code == 200
    data = r.json()
    assert len(data) >= 2
    row = data[0]
    for f in ("user_count", "asset_count", "scan_count", "plan", "status"):
        assert f in row


async def test_operator_suspends_org_blocks_user(client, monkeypatch):
    monkeypatch.setattr(settings, "OPERATOR_EMAILS", "op2@test.com")
    op = await _register(client, "op2@test.com", "Op2 Org")
    cust = await _register(client, "cust2@test.com", "Cust2 Org")
    oph = _auth(op["access_token"])

    orgs = (await client.get("/api/v1/admin/orgs", headers=oph)).json()
    cust_org = next(o for o in orgs if o["name"] == "Cust2 Org")

    # customer works before suspension
    assert (await client.get("/api/v1/org", headers=_auth(cust["access_token"]))).status_code == 200

    # operator suspends
    r = await client.patch(f"/api/v1/admin/orgs/{cust_org['id']}",
                           json={"status": "suspended"}, headers=oph)
    assert r.status_code == 200
    assert r.json()["status"] == "suspended"

    # customer now blocked
    blocked = await client.get("/api/v1/org", headers=_auth(cust["access_token"]))
    assert blocked.status_code == 403


async def test_operator_changes_plan(client, monkeypatch):
    monkeypatch.setattr(settings, "OPERATOR_EMAILS", "op3@test.com")
    op = await _register(client, "op3@test.com", "Op3 Org")
    oph = _auth(op["access_token"])
    orgs = (await client.get("/api/v1/admin/orgs", headers=oph)).json()
    org_id = orgs[0]["id"]

    r = await client.patch(f"/api/v1/admin/orgs/{org_id}", json={"plan": "mid"}, headers=oph)
    assert r.status_code == 200
    assert r.json()["plan"] == "mid"

    bad = await client.patch(f"/api/v1/admin/orgs/{org_id}", json={"plan": "nope"}, headers=oph)
    assert bad.status_code == 400


async def test_platform_stats(client, monkeypatch):
    monkeypatch.setattr(settings, "OPERATOR_EMAILS", "op4@test.com")
    op = await _register(client, "op4@test.com")
    r = await client.get("/api/v1/admin/stats", headers=_auth(op["access_token"]))
    assert r.status_code == 200
    d = r.json()
    assert d["total_orgs"] >= 1
    assert "orgs_by_plan" in d


# ── Blog / CMS ────────────────────────────────────────────────────────────────

async def test_blog_draft_hidden_until_published(client, monkeypatch):
    monkeypatch.setattr(settings, "OPERATOR_EMAILS", "blog@test.com")
    op = await _register(client, "blog@test.com")
    oph = _auth(op["access_token"])

    created = await client.post("/api/v1/admin/posts", headers=oph, json={
        "title": "PQC is coming to Indian fintech",
        "body": "# Hello\nSEBI CSCRF...", "excerpt": "Why now", "tags": ["pqc", "india"],
    })
    assert created.status_code == 200
    post = created.json()
    assert post["status"] == "draft"
    slug = post["slug"]

    # draft NOT in public list, and 404 by slug
    assert all(p["slug"] != slug for p in (await client.get("/api/v1/blog")).json())
    assert (await client.get(f"/api/v1/blog/{slug}")).status_code == 404

    # publish
    pub = await client.patch(f"/api/v1/admin/posts/{post['id']}", headers=oph, json={"status": "published"})
    assert pub.status_code == 200
    assert pub.json()["published_at"] is not None

    # now visible publicly
    assert any(p["slug"] == slug for p in (await client.get("/api/v1/blog")).json())
    got = await client.get(f"/api/v1/blog/{slug}")
    assert got.status_code == 200
    assert got.json()["body"].startswith("# Hello")


async def test_blog_create_requires_operator(client):
    u = await _register(client, "notop@test.com")
    r = await client.post("/api/v1/admin/posts", headers=_auth(u["access_token"]),
                          json={"title": "nope", "body": "x"})
    assert r.status_code == 403


async def test_blog_delete(client, monkeypatch):
    monkeypatch.setattr(settings, "OPERATOR_EMAILS", "blog2@test.com")
    op = await _register(client, "blog2@test.com")
    oph = _auth(op["access_token"])
    pid = (await client.post("/api/v1/admin/posts", headers=oph,
                             json={"title": "temp", "body": "x"})).json()["id"]
    assert (await client.delete(f"/api/v1/admin/posts/{pid}", headers=oph)).status_code == 204
    assert all(p["id"] != pid for p in (await client.get("/api/v1/admin/posts", headers=oph)).json())
