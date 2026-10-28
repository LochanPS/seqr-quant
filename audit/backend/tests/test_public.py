"""Tests for POST /api/v1/public/scan (unauthenticated free-scan endpoint)."""
import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _ai(ip: str):
    """Build a socket.getaddrinfo-shaped return value for a single address."""
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_result(**overrides) -> MagicMock:
    """Return a MagicMock shaped like DomainScanResult."""
    r = MagicMock()
    r.domain = "google.com"
    r.reachable = True
    r.tls_version = "TLS_1_3"
    r.cert_algorithm = "RSA-2048"
    r.cert = None
    r.key_exchange_algorithm = "X25519"
    r.hybrid_status = "none"
    r.pqc_hybrid_offered = False
    r.pqc_only_offered = False
    r.pqc_active_supported = False
    r.pqc_active_group = ""
    r.scan_target = "direct"
    r.origin_assessed = True
    r.deployment_level = 1
    r.deployment_level_name = "Modern Classical"
    r.crypto_agility_score = 4.5
    r.cdn_detected = True
    r.cdn_provider = "Cloudflare"
    r.scan_duration_ms = 1234
    r.scan_outcome = "success"
    for k, v in overrides.items():
        setattr(r, k, v)
    return r


@pytest.fixture(autouse=True)
def clear_rate_store():
    """Isolate rate-limit state between tests (now lives in app.ratelimit._mem)."""
    from app.ratelimit import _mem
    _mem.clear()
    yield
    _mem.clear()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

async def test_public_scan_valid_domain(client):
    fake = _fake_result()
    with (
        patch("app.routers.public._run_scanner", AsyncMock(return_value=fake)),
        patch("app.routers.public.socket.getaddrinfo", return_value=_ai("8.8.8.8")),
    ):
        r = await client.post(
            "/api/v1/public/scan", json={"domain": "google.com"}
        )

    assert r.status_code == 200
    data = r.json()
    # Excluded fields must not appear
    assert "estimated_hndl_exposure" not in data
    assert "pqc_migration_priority" not in data
    assert "threat_timeline" not in data
    assert "scan_confidence" not in data
    # Measured fields must appear
    assert "tls_version" in data
    assert "cert_algorithm" in data
    assert "deployment_level" in data
    assert data["reachable"] is True


async def test_public_scan_rejects_private_ip(client):
    r = await client.post(
        "/api/v1/public/scan", json={"domain": "localhost"}
    )
    assert r.status_code == 400


async def test_public_scan_rejects_internal(client):
    r = await client.post(
        "/api/v1/public/scan", json={"domain": "test.internal"}
    )
    assert r.status_code == 400


async def test_public_scan_rejects_local_suffix(client):
    r = await client.post(
        "/api/v1/public/scan", json={"domain": "myserver.local"}
    )
    assert r.status_code == 400


async def test_public_scan_rejects_private_resolved_ip(client):
    """Domain looks valid but resolves to an RFC-1918 address."""
    with patch(
        "app.routers.public.socket.getaddrinfo", return_value=_ai("192.168.1.1")
    ):
        r = await client.post(
            "/api/v1/public/scan", json={"domain": "internal.example.com"}
        )
    assert r.status_code == 400


async def test_public_scan_rejects_rebinding_connected_private_ip(client):
    """DNS-rebinding guard: validation passes (public IP) but the scanner
    actually connects to a private IP — results must be rejected."""
    fake = _fake_result(ip_address_scanned="10.0.0.5")
    with (
        patch("app.routers.public._run_scanner", AsyncMock(return_value=fake)),
        patch("app.routers.public.socket.getaddrinfo", return_value=_ai("8.8.8.8")),
    ):
        r = await client.post(
            "/api/v1/public/scan", json={"domain": "rebind.example.com"}
        )
    assert r.status_code == 400


async def test_public_scan_rate_limit(client):
    fake = _fake_result()
    with (
        patch("app.routers.public._run_scanner", AsyncMock(return_value=fake)),
        patch("app.routers.public.socket.getaddrinfo", return_value=_ai("8.8.8.8")),
    ):
        for _ in range(5):
            r = await client.post(
                "/api/v1/public/scan", json={"domain": "google.com"}
            )
            assert r.status_code == 200

        # 6th request — same IP, same window → 429
        r = await client.post(
            "/api/v1/public/scan", json={"domain": "google.com"}
        )

    assert r.status_code == 429
    assert "Rate limit reached" in r.json()["detail"]


async def test_public_scan_invalid_format(client):
    r = await client.post(
        "/api/v1/public/scan", json={"domain": "not a domain!!"}
    )
    assert r.status_code == 400


async def test_public_scan_invalid_format_bare_word(client):
    r = await client.post(
        "/api/v1/public/scan", json={"domain": "nodot"}
    )
    assert r.status_code == 400


async def test_public_scan_unreachable_domain(client):
    fake = _fake_result(reachable=False, scan_outcome="dns_failure")
    with (
        patch("app.routers.public._run_scanner", AsyncMock(return_value=fake)),
        patch("app.routers.public.socket.getaddrinfo", return_value=_ai("1.2.3.4")),
    ):
        r = await client.post(
            "/api/v1/public/scan", json={"domain": "notexist.example.com"}
        )

    assert r.status_code == 200
    data = r.json()
    assert data["reachable"] is False
    assert data["error_category"] == "dns_failure"


async def test_public_scan_response_excludes_hndl_fields(client):
    """Belt-and-suspenders: check JSON keys at the serialisation level."""
    fake = _fake_result()
    # Attach inferred fields to the mock — they must NOT appear in response
    fake.estimated_hndl_exposure = "high"
    fake.pqc_migration_priority = 9.5
    fake.threat_timeline = "immediate"
    fake.scan_confidence = "high"

    with (
        patch("app.routers.public._run_scanner", AsyncMock(return_value=fake)),
        patch("app.routers.public.socket.getaddrinfo", return_value=_ai("8.8.8.8")),
    ):
        r = await client.post(
            "/api/v1/public/scan", json={"domain": "google.com"}
        )

    assert r.status_code == 200
    data = r.json()
    for forbidden in (
        "estimated_hndl_exposure",
        "pqc_migration_priority",
        "threat_timeline",
        "scan_confidence",
    ):
        assert forbidden not in data, f"Forbidden field '{forbidden}' leaked into public response"
