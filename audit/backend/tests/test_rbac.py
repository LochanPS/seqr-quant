"""RBAC permission-matrix + tenancy tests (A5).

Verifies each role's capabilities against the matrix in app.rbac, that the depth beyond
admin/member is enforced in the routers (viewer/auditor are read-only; analyst can write
but not manage users/org), and that RBAC never weakens the multi-tenant org boundary.
"""
import uuid

import pytest

from app.rbac import (
    ALL_PERMISSIONS,
    ASSETS_WRITE,
    AUDIT_READ,
    ORG_MANAGE,
    ROLE_PERMISSIONS,
    USERS_MANAGE,
    has_permission,
    permissions_for,
)


# --------------------------------------------------------------------------- unit
def test_matrix_admin_has_everything():
    assert permissions_for("admin") == ALL_PERMISSIONS


def test_matrix_read_only_roles_have_no_writes():
    for role in ("viewer", "auditor"):
        assert not has_permission(role, ASSETS_WRITE)
        assert not has_permission(role, ORG_MANAGE)
        assert not has_permission(role, USERS_MANAGE)


def test_matrix_auditor_reads_audit_viewer_does_not():
    assert has_permission("auditor", AUDIT_READ)
    assert not has_permission("viewer", AUDIT_READ)
    assert has_permission("admin", AUDIT_READ)


def test_matrix_analyst_writes_but_cannot_manage():
    assert has_permission("analyst", ASSETS_WRITE)
    assert not has_permission("analyst", USERS_MANAGE)
    assert not has_permission("analyst", ORG_MANAGE)
    assert not has_permission("analyst", AUDIT_READ)


def test_member_is_analyst_alias():
    assert ROLE_PERMISSIONS["member"] == ROLE_PERMISSIONS["analyst"]


def test_unknown_role_grants_nothing():
    assert permissions_for("nobody") == frozenset()
    assert not has_permission(None, ASSETS_WRITE)


# ----------------------------------------------------------------------- helpers
async def _register(client, email, org):
    r = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "SecurePass123!", "name": "T", "org_name": org},
    )
    assert r.status_code == 200
    return r.json()


async def _login(client, email):
    r = await client.post("/api/v1/auth/login", json={"email": email, "password": "SecurePass123!"})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


async def _make_user_with_role(client, admin_token, email, role):
    """Invite a user at a role, then log in as them and return the access token."""
    r = await client.post(
        "/api/v1/org/users/invite",
        json={"email": email, "role": role},
        headers=_auth(admin_token),
    )
    assert r.status_code == 200, r.text
    temp_pw = r.json()["temporary_password"]
    lr = await client.post("/api/v1/auth/login", json={"email": email, "password": temp_pw})
    assert lr.status_code == 200, lr.text
    return lr.json()["access_token"]


# ------------------------------------------------------------------- enforcement
@pytest.mark.asyncio
async def test_invite_rejects_invalid_role(client):
    admin = await _register(client, "admin@corp.com", "Corp")
    r = await client.post(
        "/api/v1/org/users/invite",
        json={"email": "x@corp.com", "role": "superuser"},
        headers=_auth(admin["access_token"]),
    )
    assert r.status_code == 400
    assert "role must be one of" in r.text


@pytest.mark.asyncio
async def test_viewer_cannot_write_assets(client):
    admin = await _register(client, "admin@corp.com", "Corp")
    viewer_token = await _make_user_with_role(client, admin["access_token"], "viewer@corp.com", "viewer")

    # viewer can read
    r = await client.get("/api/v1/assets", headers=_auth(viewer_token))
    assert r.status_code == 200

    # viewer cannot create
    r = await client.post(
        "/api/v1/assets",
        json={"type": "domain", "identifier": "example.com"},
        headers=_auth(viewer_token),
    )
    assert r.status_code == 403
    assert "viewer" in r.text


@pytest.mark.asyncio
async def test_analyst_can_write_assets_but_not_manage_users(client):
    admin = await _register(client, "admin@corp.com", "Corp")
    analyst_token = await _make_user_with_role(client, admin["access_token"], "an@corp.com", "analyst")

    r = await client.post(
        "/api/v1/assets",
        json={"type": "domain", "identifier": "example.com"},
        headers=_auth(analyst_token),
    )
    assert r.status_code == 200

    # cannot invite users
    r = await client.post(
        "/api/v1/org/users/invite",
        json={"email": "new@corp.com", "role": "viewer"},
        headers=_auth(analyst_token),
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_auditor_can_read_audit_viewer_cannot(client):
    admin = await _register(client, "admin@corp.com", "Corp")
    auditor_token = await _make_user_with_role(client, admin["access_token"], "aud@corp.com", "auditor")
    viewer_token = await _make_user_with_role(client, admin["access_token"], "vw@corp.com", "viewer")

    assert (await client.get("/api/v1/audit", headers=_auth(auditor_token))).status_code == 200
    assert (await client.get("/api/v1/audit", headers=_auth(admin["access_token"]))).status_code == 200
    assert (await client.get("/api/v1/audit", headers=_auth(viewer_token))).status_code == 403


@pytest.mark.asyncio
async def test_cannot_remove_last_admin(client):
    admin = await _register(client, "admin@corp.com", "Corp")
    # find own user id
    users = (await client.get("/api/v1/org/users", headers=_auth(admin["access_token"]))).json()
    admin_id = next(u["id"] for u in users if u["email"] == "admin@corp.com")
    r = await client.patch(
        f"/api/v1/org/users/{admin_id}/role",
        json={"role": "viewer"},
        headers=_auth(admin["access_token"]),
    )
    assert r.status_code == 400
    assert "last admin" in r.text


@pytest.mark.asyncio
async def test_rbac_preserves_tenancy(client):
    """A different org's admin still cannot touch this org's assets (404, not RBAC 403)."""
    a = await _register(client, "a@one.com", "OrgOne")
    b = await _register(client, "b@two.com", "OrgTwo")

    # OrgOne creates an asset
    r = await client.post(
        "/api/v1/assets",
        json={"type": "domain", "identifier": "one.example"},
        headers=_auth(a["access_token"]),
    )
    asset_id = r.json()["id"]

    # OrgTwo admin (has assets:write) must not see or delete it — cross-tenant 404
    r = await client.get(f"/api/v1/assets/{asset_id}", headers=_auth(b["access_token"]))
    assert r.status_code == 404
    r = await client.delete(f"/api/v1/assets/{asset_id}", headers=_auth(b["access_token"]))
    assert r.status_code == 404
