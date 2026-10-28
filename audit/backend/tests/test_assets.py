from unittest.mock import MagicMock, patch

import pytest


async def _get_token(client) -> str:
    r = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "assets_user@testcorp.com",
            "password": "SecurePass123!",
            "name": "Asset User",
            "org_name": "Asset Corp",
        },
    )
    assert r.status_code == 200
    return r.json()["access_token"]


async def test_create_domain_asset(client):
    token = await _get_token(client)
    r = await client.post(
        "/api/v1/assets",
        json={
            "type": "domain",
            "name": "Razorpay API",
            "identifier": "api.razorpay.com",
            "data_sensitivity": "confidential",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["identifier"] == "api.razorpay.com"
    assert data["type"] == "domain"
    assert data["data_sensitivity"] == "confidential"


async def test_create_asset_invalid_type(client):
    token = await _get_token(client)
    r = await client.post(
        "/api/v1/assets",
        json={"type": "aws_account", "identifier": "123456789"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 400


@pytest.mark.parametrize(
    "asset_type",
    ["ssh", "smtp", "imap", "pop3", "postgres", "mongodb", "amqp", "grpc", "mysql"],
)
async def test_create_protocol_asset(client, asset_type):
    token = await _get_token(client)
    r = await client.post(
        "/api/v1/assets",
        json={"type": asset_type, "identifier": f"{asset_type}.example.com"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["type"] == asset_type


async def test_create_asset_invalid_domain(client):
    token = await _get_token(client)
    r = await client.post(
        "/api/v1/assets",
        json={"type": "domain", "identifier": "not a domain!"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 400


async def test_list_assets_returns_own_org_only(client):
    # Org 1
    r1 = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "org1@test.com",
            "password": "Pass123!",
            "name": "Org1 User",
            "org_name": "Org One",
        },
    )
    token1 = r1.json()["access_token"]
    await client.post(
        "/api/v1/assets",
        json={"type": "domain", "identifier": "org1.com"},
        headers={"Authorization": f"Bearer {token1}"},
    )

    # Org 2
    r2 = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "org2@test.com",
            "password": "Pass123!",
            "name": "Org2 User",
            "org_name": "Org Two",
        },
    )
    token2 = r2.json()["access_token"]
    await client.post(
        "/api/v1/assets",
        json={"type": "domain", "identifier": "org2.com"},
        headers={"Authorization": f"Bearer {token2}"},
    )

    list1 = await client.get("/api/v1/assets", headers={"Authorization": f"Bearer {token1}"})
    list2 = await client.get("/api/v1/assets", headers={"Authorization": f"Bearer {token2}"})

    assert list1.status_code == 200
    assert list2.status_code == 200
    ids1 = {a["identifier"] for a in list1.json()}
    ids2 = {a["identifier"] for a in list2.json()}
    assert ids1 == {"org1.com"}
    assert ids2 == {"org2.com"}


async def test_get_asset_detail(client):
    token = await _get_token(client)
    create_r = await client.post(
        "/api/v1/assets",
        json={"type": "domain", "identifier": "detail.example.com"},
        headers={"Authorization": f"Bearer {token}"},
    )
    asset_id = create_r.json()["id"]

    r = await client.get(f"/api/v1/assets/{asset_id}", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["id"] == asset_id


async def test_delete_asset(client):
    token = await _get_token(client)
    create_r = await client.post(
        "/api/v1/assets",
        json={"type": "domain", "identifier": "delete.example.com"},
        headers={"Authorization": f"Bearer {token}"},
    )
    asset_id = create_r.json()["id"]

    del_r = await client.delete(
        f"/api/v1/assets/{asset_id}", headers={"Authorization": f"Bearer {token}"}
    )
    assert del_r.status_code == 204

    get_r = await client.get(
        f"/api/v1/assets/{asset_id}", headers={"Authorization": f"Bearer {token}"}
    )
    assert get_r.status_code == 404


async def test_trigger_scan_returns_scan_id(client):
    token = await _get_token(client)
    create_r = await client.post(
        "/api/v1/assets",
        json={"type": "domain", "identifier": "scan.example.com"},
        headers={"Authorization": f"Bearer {token}"},
    )
    asset_id = create_r.json()["id"]

    mock_task = MagicMock()
    with patch("app.routers.assets.run_network_scan") as mock_scan:
        mock_scan.delay.return_value = mock_task
        r = await client.post(
            f"/api/v1/assets/{asset_id}/scan",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert r.status_code == 200
    data = r.json()
    assert "scan_id" in data
    assert data["status"] == "queued"
    mock_scan.delay.assert_called_once()


async def test_get_scan_status(client):
    token = await _get_token(client)
    create_r = await client.post(
        "/api/v1/assets",
        json={"type": "domain", "identifier": "scanstatus.example.com"},
        headers={"Authorization": f"Bearer {token}"},
    )
    asset_id = create_r.json()["id"]

    with patch("app.routers.assets.run_network_scan") as mock_scan:
        mock_scan.delay.return_value = MagicMock()
        scan_r = await client.post(
            f"/api/v1/assets/{asset_id}/scan",
            headers={"Authorization": f"Bearer {token}"},
        )

    scan_id = scan_r.json()["scan_id"]
    status_r = await client.get(
        f"/api/v1/scans/{scan_id}", headers={"Authorization": f"Bearer {token}"}
    )
    assert status_r.status_code == 200
    assert status_r.json()["status"] == "queued"


async def test_list_scans(client):
    token = await _get_token(client)
    create_r = await client.post(
        "/api/v1/assets",
        json={"type": "domain", "identifier": "listscans.example.com"},
        headers={"Authorization": f"Bearer {token}"},
    )
    asset_id = create_r.json()["id"]

    with patch("app.routers.assets.run_network_scan") as mock_scan:
        mock_scan.delay.return_value = MagicMock()
        await client.post(
            f"/api/v1/assets/{asset_id}/scan",
            headers={"Authorization": f"Bearer {token}"},
        )

    r = await client.get("/api/v1/scans", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert len(r.json()) >= 1
