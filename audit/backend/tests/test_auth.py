import pyotp
import pytest


async def test_register_creates_org_and_user(client):
    r = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "test@company.com",
            "password": "SecurePass123!",
            "name": "Test User",
            "org_name": "Test Corp",
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["user"]["email"] == "test@company.com"
    assert data["user"]["role"] == "admin"
    assert data["org"]["name"] == "Test Corp"


async def test_login_returns_tokens(client):
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "login@test.com",
            "password": "MyPass456!",
            "name": "Login User",
            "org_name": "Login Corp",
        },
    )
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "login@test.com", "password": "MyPass456!"},
    )
    assert r.status_code == 200
    data = r.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


async def test_invalid_password_returns_401(client):
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "secure@test.com",
            "password": "RealPass789!",
            "name": "Secure User",
            "org_name": "Secure Corp",
        },
    )
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "secure@test.com", "password": "WrongPassword"},
    )
    assert r.status_code == 401


async def test_refresh_token_works(client, registered_user):
    r = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": registered_user["refresh_token"]},
    )
    assert r.status_code == 200
    assert "access_token" in r.json()


async def test_create_api_key(client, registered_user):
    token = registered_user["access_token"]
    r = await client.post(
        "/api/v1/auth/api-keys",
        json={"name": "CI/CD key", "scopes": ["scan:read", "scan:write"]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["key"].startswith("sq_live_")
    assert len(data["key"]) > 15
    assert data["name"] == "CI/CD key"
    assert "scan:read" in data["scopes"]


async def test_api_key_not_returned_twice(client, registered_user):
    token = registered_user["access_token"]
    create_r = await client.post(
        "/api/v1/auth/api-keys",
        json={"name": "secret key", "scopes": ["scan:read"]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert create_r.status_code == 200
    full_key = create_r.json()["key"]

    list_r = await client.get(
        "/api/v1/auth/api-keys",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert list_r.status_code == 200
    keys = list_r.json()

    # Full key must not appear in any field of the list response
    assert all("key" not in k for k in keys)
    assert all(k["key_prefix"] != full_key for k in keys)


async def test_duplicate_email_returns_400(client):
    payload = {
        "email": "dup@test.com",
        "password": "Pass123!",
        "name": "Dup User",
        "org_name": "Dup Corp",
    }
    r1 = await client.post("/api/v1/auth/register", json=payload)
    assert r1.status_code == 200
    r2 = await client.post("/api/v1/auth/register", json=payload)
    assert r2.status_code == 400


async def test_logout_returns_ok(client, registered_user):
    token = registered_user["access_token"]
    r = await client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200


async def test_list_api_keys(client, registered_user):
    token = registered_user["access_token"]
    await client.post(
        "/api/v1/auth/api-keys",
        json={"name": "key-1", "scopes": []},
        headers={"Authorization": f"Bearer {token}"},
    )
    await client.post(
        "/api/v1/auth/api-keys",
        json={"name": "key-2", "scopes": ["scan:read"]},
        headers={"Authorization": f"Bearer {token}"},
    )
    r = await client.get("/api/v1/auth/api-keys", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    keys = r.json()
    assert len(keys) == 2
    names = {k["name"] for k in keys}
    assert names == {"key-1", "key-2"}


async def test_revoke_api_key(client, registered_user):
    token = registered_user["access_token"]
    create_r = await client.post(
        "/api/v1/auth/api-keys",
        json={"name": "to-revoke", "scopes": []},
        headers={"Authorization": f"Bearer {token}"},
    )
    key_id = create_r.json()["id"]

    del_r = await client.delete(
        f"/api/v1/auth/api-keys/{key_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert del_r.status_code == 204

    list_r = await client.get("/api/v1/auth/api-keys", headers={"Authorization": f"Bearer {token}"})
    assert all(k["id"] != key_id for k in list_r.json())


# ── API-key authentication ────────────────────────────────────────────────────

async def test_api_key_authenticates_requests(client, registered_user):
    """An sq_live_ API key works as a bearer token for authenticated routes."""
    jwt_token = registered_user["access_token"]
    key = (await client.post(
        "/api/v1/auth/api-keys", json={"name": "ci", "scopes": []},
        headers={"Authorization": f"Bearer {jwt_token}"},
    )).json()["key"]

    r = await client.get("/api/v1/org", headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 200


async def test_invalid_api_key_rejected(client):
    r = await client.get(
        "/api/v1/org",
        headers={"Authorization": "Bearer sq_live_totallyfakekeyvalue"},
    )
    assert r.status_code == 401


# ── Logout invalidates outstanding tokens ─────────────────────────────────────

async def test_logout_invalidates_token(client, registered_user):
    token = registered_user["access_token"]
    # token works before logout
    assert (await client.get("/api/v1/org", headers={"Authorization": f"Bearer {token}"})).status_code == 200
    # logout
    assert (await client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})).status_code == 200
    # same token now rejected
    r = await client.get("/api/v1/org", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


# ── MFA login flow ────────────────────────────────────────────────────────────

async def test_mfa_login_flow(client):
    reg = (await client.post("/api/v1/auth/register", json={
        "email": "mfa@test.com", "password": "MfaPass123!", "name": "MFA", "org_name": "MFA Corp",
    })).json()
    token = reg["access_token"]
    h = {"Authorization": f"Bearer {token}"}

    secret = (await client.post("/api/v1/auth/mfa/setup", headers=h)).json()["secret"]
    code = pyotp.TOTP(secret).now()
    assert (await client.post("/api/v1/auth/mfa/verify", json={"totp_code": code}, headers=h)).status_code == 200

    # Now login requires MFA → returns temp_token, no access token
    login = (await client.post("/api/v1/auth/login",
                               json={"email": "mfa@test.com", "password": "MfaPass123!"})).json()
    assert login.get("mfa_required") is True
    assert "access_token" not in login

    # Exchange temp_token + TOTP for real tokens
    mfa_login = await client.post("/api/v1/auth/mfa/login", json={
        "temp_token": login["temp_token"], "totp_code": pyotp.TOTP(secret).now(),
    })
    assert mfa_login.status_code == 200
    assert "access_token" in mfa_login.json()


async def test_mfa_login_rejects_bad_code(client):
    reg = (await client.post("/api/v1/auth/register", json={
        "email": "mfa2@test.com", "password": "MfaPass123!", "name": "MFA2", "org_name": "MFA2 Corp",
    })).json()
    h = {"Authorization": f"Bearer {reg['access_token']}"}
    secret = (await client.post("/api/v1/auth/mfa/setup", headers=h)).json()["secret"]
    await client.post("/api/v1/auth/mfa/verify", json={"totp_code": pyotp.TOTP(secret).now()}, headers=h)
    login = (await client.post("/api/v1/auth/login",
                               json={"email": "mfa2@test.com", "password": "MfaPass123!"})).json()
    r = await client.post("/api/v1/auth/mfa/login",
                          json={"temp_token": login["temp_token"], "totp_code": "000000"})
    assert r.status_code == 401
