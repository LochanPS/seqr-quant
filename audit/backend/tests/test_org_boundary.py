"""
Multi-tenant org boundary isolation tests.

Proves org A cannot access org B's resources via any route that
accepts a resource ID.  Every test must assert HTTP 404 (not 200 or 403).
"""
from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _register_and_login(client, email: str, org_name: str) -> str:
    r = await client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": "SecurePass123!",
            "name": "Test User",
            "org_name": org_name,
        },
    )
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


async def _create_asset(client, token: str, identifier: str) -> str:
    r = await client.post(
        "/api/v1/assets",
        json={"type": "domain", "identifier": identifier},
        headers=_auth(token),
    )
    assert r.status_code == 200, r.text
    return r.json()["id"]


async def _create_scan(client, token: str, asset_id: str) -> str:
    with patch("app.routers.assets.run_network_scan") as mock:
        mock.delay.return_value = MagicMock()
        r = await client.post(
            f"/api/v1/assets/{asset_id}/scan",
            headers=_auth(token),
        )
    assert r.status_code == 200, r.text
    return r.json()["scan_id"]


# ---------------------------------------------------------------------------
# Asset isolation
# ---------------------------------------------------------------------------

async def test_org_a_cannot_get_org_b_asset(client):
    tok_a = await _register_and_login(client, "a1@orga.com", "Org A")
    tok_b = await _register_and_login(client, "b1@orgb.com", "Org B")

    # Org A creates an asset
    asset_id = await _create_asset(client, tok_a, "orga-secret.example.com")

    # Org B tries to read it — must get 404
    r = await client.get(f"/api/v1/assets/{asset_id}", headers=_auth(tok_b))
    assert r.status_code == 404, f"Expected 404, got {r.status_code}: {r.text}"


async def test_org_a_cannot_delete_org_b_asset(client):
    tok_a = await _register_and_login(client, "a2@orga.com", "Org A Del")
    tok_b = await _register_and_login(client, "b2@orgb.com", "Org B Del")

    asset_id = await _create_asset(client, tok_a, "orga-del.example.com")

    # Org B tries to delete — must get 404
    r = await client.delete(f"/api/v1/assets/{asset_id}", headers=_auth(tok_b))
    assert r.status_code == 404, f"Expected 404, got {r.status_code}: {r.text}"

    # Asset still exists for org A
    r_check = await client.get(f"/api/v1/assets/{asset_id}", headers=_auth(tok_a))
    assert r_check.status_code == 200


async def test_org_a_cannot_trigger_scan_on_org_b_asset(client):
    tok_a = await _register_and_login(client, "a3@orga.com", "Org A Scan")
    tok_b = await _register_and_login(client, "b3@orgb.com", "Org B Scan")

    asset_id = await _create_asset(client, tok_a, "orga-scan.example.com")

    with patch("app.routers.assets.run_network_scan") as mock:
        mock.delay.return_value = MagicMock()
        r = await client.post(f"/api/v1/assets/{asset_id}/scan", headers=_auth(tok_b))
    assert r.status_code == 404, f"Expected 404, got {r.status_code}: {r.text}"


async def test_org_list_never_returns_other_org_assets(client):
    tok_a = await _register_and_login(client, "a4@orga.com", "Org A List")
    tok_b = await _register_and_login(client, "b4@orgb.com", "Org B List")

    await _create_asset(client, tok_a, "list-orga.example.com")
    await _create_asset(client, tok_b, "list-orgb.example.com")

    list_a = await client.get("/api/v1/assets", headers=_auth(tok_a))
    list_b = await client.get("/api/v1/assets", headers=_auth(tok_b))

    ids_a = {a["identifier"] for a in list_a.json()}
    ids_b = {a["identifier"] for a in list_b.json()}

    assert "list-orgb.example.com" not in ids_a
    assert "list-orga.example.com" not in ids_b
    assert "list-orga.example.com" in ids_a
    assert "list-orgb.example.com" in ids_b


# ---------------------------------------------------------------------------
# Scan isolation
# ---------------------------------------------------------------------------

async def test_org_a_cannot_get_org_b_scan(client):
    tok_a = await _register_and_login(client, "sa1@orga.com", "Org SA")
    tok_b = await _register_and_login(client, "sb1@orgb.com", "Org SB")

    asset_id = await _create_asset(client, tok_a, "scan-orga.example.com")
    scan_id = await _create_scan(client, tok_a, asset_id)

    r = await client.get(f"/api/v1/scans/{scan_id}", headers=_auth(tok_b))
    assert r.status_code == 404, f"Expected 404, got {r.status_code}: {r.text}"


async def test_org_b_scan_list_excludes_org_a_scans(client):
    tok_a = await _register_and_login(client, "sa2@orga.com", "Org SA2")
    tok_b = await _register_and_login(client, "sb2@orgb.com", "Org SB2")

    asset_a = await _create_asset(client, tok_a, "sclist-orga.example.com")
    await _create_scan(client, tok_a, asset_a)

    # Org B has no scans
    r = await client.get("/api/v1/scans", headers=_auth(tok_b))
    assert r.status_code == 200
    assert len(r.json()) == 0


# ---------------------------------------------------------------------------
# UUID that belongs to nobody — also 404
# ---------------------------------------------------------------------------

async def test_nonexistent_asset_id_returns_404(client):
    tok = await _register_and_login(client, "none1@orga.com", "Org None")
    ghost_id = str(uuid.uuid4())
    r = await client.get(f"/api/v1/assets/{ghost_id}", headers=_auth(tok))
    assert r.status_code == 404


async def test_nonexistent_scan_id_returns_404(client):
    tok = await _register_and_login(client, "none2@orga.com", "Org None2")
    ghost_id = str(uuid.uuid4())
    r = await client.get(f"/api/v1/scans/{ghost_id}", headers=_auth(tok))
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Auth required — unauthenticated requests must be 401/403
# ---------------------------------------------------------------------------

async def test_unauthenticated_asset_access_is_rejected(client):
    tok = await _register_and_login(client, "auth1@orga.com", "Org Auth")
    asset_id = await _create_asset(client, tok, "auth-test.example.com")

    r = await client.get(f"/api/v1/assets/{asset_id}")
    assert r.status_code in (401, 403)


async def test_unauthenticated_scan_access_is_rejected(client):
    tok = await _register_and_login(client, "auth2@orga.com", "Org Auth2")
    asset_id = await _create_asset(client, tok, "auth-scan.example.com")
    scan_id = await _create_scan(client, tok, asset_id)

    r = await client.get(f"/api/v1/scans/{scan_id}")
    assert r.status_code in (401, 403)
