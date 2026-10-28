"""Enterprise SSO / OIDC tests (A5).

No live IdP: the id_token is minted locally with a real RSA keypair and the JWKS /
token-exchange HTTP calls are stubbed. This exercises the security-critical path
(signature + iss/aud/exp/nonce validation) for real, plus group→role mapping, JIT
provisioning, config CRUD, and tenancy.
"""
import time
import uuid

import pytest
from authlib.jose import JsonWebKey, jwt as jose_jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.models.oidc_provider import OIDCProvider
from app.routers import sso as sso_router
from app.sso import oidc
from app.sso.crypto import decrypt_secret, encrypt_secret

ISSUER = "https://idp.example.com"
CLIENT_ID = "seqr-client"
KID = "test-key-1"


# --------------------------------------------------------------------- key fixtures
@pytest.fixture(scope="module")
def rsa_keys():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    jwks = {"keys": [JsonWebKey.import_key(pub_pem, {"kty": "RSA", "kid": KID, "use": "sig"}).as_dict()]}
    return priv_pem, jwks


def _mint_id_token(priv_pem, *, nonce="n", aud=CLIENT_ID, iss=ISSUER, email="user@idp.example.com",
                   groups=None, sub="idp-sub-1", exp_delta=300):
    now = int(time.time())
    payload = {
        "iss": iss, "aud": aud, "sub": sub, "email": email,
        "iat": now, "exp": now + exp_delta, "nonce": nonce,
    }
    if groups is not None:
        payload["groups"] = groups
    header = {"alg": "RS256", "kid": KID}
    return jose_jwt.encode(header, payload, priv_pem).decode()


def _provider(**over):
    defaults = dict(
        id=uuid.uuid4(), org_id=uuid.uuid4(), issuer=ISSUER, client_id=CLIENT_ID,
        client_secret_encrypted=encrypt_secret("shh"), scopes="openid email groups",
        groups_claim="groups", group_role_map={}, default_role="member",
        email_domain=None, auto_provision=True, enabled=True, display_name="SSO",
        discovery_url=None,
    )
    defaults.update(over)
    return OIDCProvider(**defaults)


# --------------------------------------------------------------------------- unit
def test_secret_encryption_roundtrip():
    enc = encrypt_secret("super-secret")
    assert enc != "super-secret"
    assert decrypt_secret(enc) == "super-secret"


def test_map_role_picks_strongest():
    p = _provider(group_role_map={"eng": "analyst", "sec": "admin", "ro": "viewer"})
    assert oidc.map_role(p, ["eng", "sec", "ro"]) == "admin"
    assert oidc.map_role(p, ["eng", "ro"]) == "analyst"


def test_map_role_defaults_when_no_match():
    p = _provider(group_role_map={"eng": "analyst"}, default_role="viewer")
    assert oidc.map_role(p, ["unknown"]) == "viewer"
    assert oidc.map_role(p, []) == "viewer"


def test_map_role_ignores_invalid_mapped_role():
    p = _provider(group_role_map={"eng": "wizard"}, default_role="member")
    assert oidc.map_role(p, ["eng"]) == "member"


def test_extract_identity_handles_string_groups():
    p = _provider(groups_claim="roles")
    email, sub, groups = oidc.extract_identity(p, {"email": "a@b.com", "sub": "s", "roles": "x, y z"})
    assert email == "a@b.com" and sub == "s"
    assert set(groups) == {"x", "y", "z"}


def test_state_roundtrip_and_tamper():
    pid = uuid.uuid4()
    tok = oidc.make_state(pid, "nonce-1")
    st = oidc.read_state(tok)
    assert st["pid"] == str(pid) and st["nonce"] == "nonce-1"
    with pytest.raises(oidc.OIDCError):
        oidc.read_state(tok + "tamper")


@pytest.mark.asyncio
async def test_validate_id_token_accepts_valid(rsa_keys, monkeypatch):
    priv, jwks = rsa_keys
    monkeypatch.setattr(oidc, "get_jwks", lambda uri: _async(jwks))
    p = _provider()
    tok = _mint_id_token(priv, nonce="abc", groups=["eng"])
    claims = await oidc.validate_id_token(p, {"jwks_uri": "x"}, tok, "abc")
    assert claims["email"] == "user@idp.example.com"
    assert claims["groups"] == ["eng"]


@pytest.mark.asyncio
async def test_validate_id_token_rejects_bad_aud_and_nonce(rsa_keys, monkeypatch):
    priv, jwks = rsa_keys
    monkeypatch.setattr(oidc, "get_jwks", lambda uri: _async(jwks))
    p = _provider()
    # wrong audience
    with pytest.raises(oidc.OIDCError):
        await oidc.validate_id_token(p, {"jwks_uri": "x"}, _mint_id_token(priv, aud="someone-else"), "n")
    # nonce mismatch
    with pytest.raises(oidc.OIDCError):
        await oidc.validate_id_token(p, {"jwks_uri": "x"}, _mint_id_token(priv, nonce="n1"), "n2")
    # expired
    with pytest.raises(oidc.OIDCError):
        await oidc.validate_id_token(p, {"jwks_uri": "x"}, _mint_id_token(priv, exp_delta=-10), None)


async def _async(value):
    return value


# ------------------------------------------------------------------- config CRUD
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
async def test_config_crud_secret_is_write_only(client):
    admin = await _register(client, "admin@corp.com", "Corp")
    tok = admin["access_token"]

    r = await client.put(
        "/api/v1/sso/config",
        json={
            "issuer": ISSUER, "client_id": CLIENT_ID, "client_secret": "topsecret",
            "group_role_map": {"admins": "admin", "staff": "analyst"},
            "default_role": "viewer", "email_domain": "Corp.COM",
        },
        headers=_auth(tok),
    )
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["configured"] is True
    assert out["has_client_secret"] is True
    assert "client_secret" not in out
    assert out["email_domain"] == "corp.com"  # normalised
    assert out["redirect_uri"].endswith("/api/v1/sso/oidc/callback")

    # GET never returns the secret
    g = (await client.get("/api/v1/sso/config", headers=_auth(tok))).json()
    assert "client_secret" not in g and g["has_client_secret"] is True

    # update without secret keeps it
    r = await client.put(
        "/api/v1/sso/config",
        json={"issuer": ISSUER, "client_id": CLIENT_ID, "default_role": "member"},
        headers=_auth(tok),
    )
    assert r.status_code == 200 and r.json()["has_client_secret"] is True


@pytest.mark.asyncio
async def test_config_rejects_invalid_role_and_non_admin(client):
    admin = await _register(client, "admin@corp.com", "Corp")
    tok = admin["access_token"]

    r = await client.put(
        "/api/v1/sso/config",
        json={"issuer": ISSUER, "client_id": CLIENT_ID, "client_secret": "s",
              "group_role_map": {"g": "wizard"}},
        headers=_auth(tok),
    )
    assert r.status_code == 400

    # invite a viewer, who must not manage SSO config
    inv = await client.post("/api/v1/org/users/invite", json={"email": "v@corp.com", "role": "viewer"},
                            headers=_auth(tok))
    vpw = inv.json()["temporary_password"]
    vtok = (await client.post("/api/v1/auth/login", json={"email": "v@corp.com", "password": vpw})).json()["access_token"]
    r = await client.get("/api/v1/sso/config", headers=_auth(vtok))
    assert r.status_code == 403


# --------------------------------------------------------------- end-to-end flow
@pytest.mark.asyncio
async def test_start_requires_sso_enabled(client, monkeypatch):
    admin = await _register(client, "admin@corp.com", "Corp")
    await client.put(
        "/api/v1/sso/config",
        json={"issuer": ISSUER, "client_id": CLIENT_ID, "client_secret": "s", "email_domain": "corp.com"},
        headers=_auth(admin["access_token"]),
    )
    # disabled by default → 404
    monkeypatch.setattr(sso_router.settings, "SSO_ENABLED", False)
    r = await client.get("/api/v1/sso/oidc/start", params={"domain": "corp.com"})
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_start_redirects_to_idp(client, monkeypatch):
    admin = await _register(client, "admin@corp.com", "Corp")
    cfg = (await client.put(
        "/api/v1/sso/config",
        json={"issuer": ISSUER, "client_id": CLIENT_ID, "client_secret": "s", "email_domain": "corp.com"},
        headers=_auth(admin["access_token"]),
    )).json()

    monkeypatch.setattr(sso_router.settings, "SSO_ENABLED", True)

    async def fake_authz(provider, redirect_uri, state, nonce):
        return f"{ISSUER}/authorize?client_id={provider.client_id}&state={state}"

    monkeypatch.setattr(sso_router.oidc, "build_authorization_url", fake_authz)

    r = await client.get("/api/v1/sso/oidc/start", params={"provider_id": cfg["id"]},
                         follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"].startswith(f"{ISSUER}/authorize")


async def _drive_callback(client, monkeypatch, provider_id, claims):
    """Hit the callback with a valid state, stubbing the code→claims exchange."""
    monkeypatch.setattr(sso_router.settings, "SSO_ENABLED", True)

    async def fake_fetch(provider, code, redirect_uri, nonce):
        return claims

    monkeypatch.setattr(sso_router.oidc, "fetch_claims", fake_fetch)
    state = oidc.make_state(uuid.UUID(provider_id), "nonce-x")
    return await client.get("/api/v1/sso/oidc/callback", params={"code": "abc", "state": state},
                            follow_redirects=False)


def _tokens_from_location(loc):
    frag = loc.split("#", 1)[1]
    return dict(kv.split("=", 1) for kv in frag.split("&"))


@pytest.mark.asyncio
async def test_callback_provisions_and_maps_role(client, monkeypatch):
    from jose import jwt as jose

    admin = await _register(client, "admin@corp.com", "Corp")
    cfg = (await client.put(
        "/api/v1/sso/config",
        json={"issuer": ISSUER, "client_id": CLIENT_ID, "client_secret": "s",
              "group_role_map": {"seqr-admins": "admin", "seqr-staff": "analyst"},
              "default_role": "viewer"},
        headers=_auth(admin["access_token"]),
    )).json()

    # new user in the "seqr-staff" group → provisioned as analyst
    claims = {"email": "newbie@corp.com", "sub": "idp-1", "name": "New Bie", "groups": ["seqr-staff"]}
    r = await _drive_callback(client, monkeypatch, cfg["id"], claims)
    assert r.status_code == 302
    toks = _tokens_from_location(r.headers["location"])
    assert "access_token" in toks
    decoded = jose.decode(toks["access_token"], __import__("app.config", fromlist=["settings"]).settings.SECRET_KEY, algorithms=["HS256"])
    assert decoded["role"] == "analyst"

    # the provisioned user can now use the API
    me = await client.get("/api/v1/org", headers=_auth(toks["access_token"]))
    assert me.status_code == 200

    # a role change at the IdP is synced on next login (staff → admins)
    claims2 = {"email": "newbie@corp.com", "sub": "idp-1", "groups": ["seqr-admins"]}
    r2 = await _drive_callback(client, monkeypatch, cfg["id"], claims2)
    toks2 = _tokens_from_location(r2.headers["location"])
    assert jose.decode(toks2["access_token"], __import__("app.config", fromlist=["settings"]).settings.SECRET_KEY, algorithms=["HS256"])["role"] == "admin"


@pytest.mark.asyncio
async def test_callback_rejects_cross_org_email(client, monkeypatch):
    # OrgOne has an existing user; OrgTwo's IdP tries to log in that same email.
    await _register(client, "shared@corp.com", "OrgOne")
    two_admin = await _register(client, "admin@two.com", "OrgTwo")
    cfg = (await client.put(
        "/api/v1/sso/config",
        json={"issuer": ISSUER, "client_id": CLIENT_ID, "client_secret": "s"},
        headers=_auth(two_admin["access_token"]),
    )).json()

    claims = {"email": "shared@corp.com", "sub": "x", "groups": []}
    r = await _drive_callback(client, monkeypatch, cfg["id"], claims)
    assert r.status_code == 302
    assert "error=email_belongs_to_other_org" in r.headers["location"]


@pytest.mark.asyncio
async def test_callback_blocks_unprovisioned_when_disabled(client, monkeypatch):
    admin = await _register(client, "admin@corp.com", "Corp")
    cfg = (await client.put(
        "/api/v1/sso/config",
        json={"issuer": ISSUER, "client_id": CLIENT_ID, "client_secret": "s", "auto_provision": False},
        headers=_auth(admin["access_token"]),
    )).json()

    claims = {"email": "nobody@corp.com", "sub": "z", "groups": []}
    r = await _drive_callback(client, monkeypatch, cfg["id"], claims)
    assert "error=user_not_provisioned" in r.headers["location"]
