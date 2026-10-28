"""The FastAPI auth example is exercised end-to-end with Starlette's TestClient."""
import time

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture
def client(pqc_backend):
    from examples import fastapi_auth

    return TestClient(fastapi_auth.app)


def _login(client, username="alice", password="password"):
    return client.post("/login", json={"username": username, "password": password})


def test_login_issues_ml_dsa_token(client):
    resp = _login(client)
    assert resp.status_code == 200
    body = resp.json()
    assert body["algorithm"] == "ML-DSA-65"
    assert body["access_token"].count(".") == 2


def test_protected_route_accepts_valid_token(client):
    token = _login(client).json()["access_token"]
    resp = client.get("/me", headers={"authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["user"] == "alice"


def test_protected_route_rejects_missing_token(client):
    assert client.get("/me").status_code == 401


def test_protected_route_rejects_tampered_token(client):
    token = _login(client).json()["access_token"]
    h, p, s = token.split(".")
    forged = f"{h}.{p}.{s[:-4] + 'AAAA'}"
    resp = client.get("/me", headers={"authorization": f"Bearer {forged}"})
    assert resp.status_code == 401


def test_bad_credentials_rejected(client):
    assert _login(client, password="wrong").status_code == 401


def test_expired_token_rejected(client, monkeypatch):
    from examples import fastapi_auth

    monkeypatch.setattr(fastapi_auth, "TOKEN_TTL_SECONDS", -1)
    token = _login(client).json()["access_token"]
    resp = client.get("/me", headers={"authorization": f"Bearer {token}"})
    assert resp.status_code == 401
    assert "expired" in resp.json()["detail"].lower()
