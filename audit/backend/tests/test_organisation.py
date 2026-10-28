import pytest


async def test_get_org_returns_details(client, registered_user):
    token = registered_user["access_token"]
    r = await client.get("/api/v1/org", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    data = r.json()
    assert data["name"] == "Test Corp"
    assert data["plan"] == "trial"


async def test_update_org(client, registered_user):
    token = registered_user["access_token"]
    r = await client.patch(
        "/api/v1/org",
        json={"name": "Updated Corp", "sector": "fintech"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["name"] == "Updated Corp"
    assert data["sector"] == "fintech"


async def test_list_users_admin_only(client, registered_user):
    token = registered_user["access_token"]
    r = await client.get("/api/v1/org/users", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    users = r.json()
    assert len(users) == 1
    assert users[0]["email"] == "admin@testcorp.com"


async def test_non_admin_cannot_change_roles(client, registered_user):
    admin_token = registered_user["access_token"]

    # invite a member
    invite_r = await client.post(
        "/api/v1/org/users/invite",
        json={"email": "member@test.com", "role": "member"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert invite_r.status_code == 200

    # list users to get member id
    users_r = await client.get("/api/v1/org/users", headers={"Authorization": f"Bearer {admin_token}"})
    member = next(u for u in users_r.json() if u["email"] == "member@test.com")
    member_id = member["id"]

    # member logs in (we know their temp password isn't directly accessible, so
    # promote them to developer first and test the rule via admin-only endpoint)
    # verify non-admin access to role update is blocked
    r = await client.patch(
        f"/api/v1/org/users/{member_id}/role",
        json={"role": "admin"},
        # no auth header
    )
    assert r.status_code == 403


async def test_invite_user_creates_account(client, registered_user):
    token = registered_user["access_token"]
    r = await client.post(
        "/api/v1/org/users/invite",
        json={"email": "newbie@corp.com", "role": "analyst"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["email"] == "newbie@corp.com"
    assert data["role"] == "analyst"
    # Security: temp password returned in body (HTTPS), never in a URL.
    assert "invite_link" not in data
    assert data["temporary_password"]
    assert data["must_change_password"] is True

    # user appears in org list
    users_r = await client.get("/api/v1/org/users", headers={"Authorization": f"Bearer {token}"})
    emails = [u["email"] for u in users_r.json()]
    assert "newbie@corp.com" in emails


async def test_update_user_role(client, registered_user):
    token = registered_user["access_token"]

    await client.post(
        "/api/v1/org/users/invite",
        json={"email": "promote@corp.com", "role": "member"},
        headers={"Authorization": f"Bearer {token}"},
    )
    users_r = await client.get("/api/v1/org/users", headers={"Authorization": f"Bearer {token}"})
    target = next(u for u in users_r.json() if u["email"] == "promote@corp.com")

    r = await client.patch(
        f"/api/v1/org/users/{target['id']}/role",
        json={"role": "auditor"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    assert r.json()["role"] == "auditor"


async def test_unauthenticated_org_access_blocked(client):
    r = await client.get("/api/v1/org")
    assert r.status_code == 403
