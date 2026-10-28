"""A6 — async scan workers: per-org fairness cap, batch scan, live WS progress."""
from unittest.mock import MagicMock, patch

import fakeredis
import pytest

from app.tasks import throttle
from app.tasks import scan_tasks


# --- Per-org fairness throttle ---------------------------------------------

def test_org_cap_blocks_over_limit_and_releases():
    r = fakeredis.FakeStrictRedis()
    org = "org-1"
    assert throttle.acquire_org_slot(r, org, cap=2, ttl=900) is True
    assert throttle.acquire_org_slot(r, org, cap=2, ttl=900) is True
    assert throttle.inflight(r, org) == 2
    # third over the cap → rejected, counter not inflated
    assert throttle.acquire_org_slot(r, org, cap=2, ttl=900) is False
    assert throttle.inflight(r, org) == 2
    # releasing frees a slot
    throttle.release_org_slot(r, org)
    assert throttle.inflight(r, org) == 1
    assert throttle.acquire_org_slot(r, org, cap=2, ttl=900) is True


def test_org_cap_sets_ttl_on_first_acquire():
    r = fakeredis.FakeStrictRedis()
    throttle.acquire_org_slot(r, "org-x", cap=3, ttl=120)
    assert 0 < r.ttl(throttle.org_key("org-x")) <= 120


def test_org_cap_zero_is_unlimited():
    r = fakeredis.FakeStrictRedis()
    for _ in range(50):
        assert throttle.acquire_org_slot(r, "o", cap=0, ttl=900) is True


def test_release_never_goes_negative():
    r = fakeredis.FakeStrictRedis()
    throttle.release_org_slot(r, "o")
    assert throttle.inflight(r, "o") == 0


def test_orgs_are_isolated():
    r = fakeredis.FakeStrictRedis()
    assert throttle.acquire_org_slot(r, "a", cap=1, ttl=900) is True
    assert throttle.acquire_org_slot(r, "a", cap=1, ttl=900) is False
    # a different org is unaffected by org a being at cap
    assert throttle.acquire_org_slot(r, "b", cap=1, ttl=900) is True


# --- Progress publishing (no-op under fakeredis; correct shapes otherwise) --

def test_publish_is_noop_with_fakeredis():
    # default test settings → USE_FAKE_REDIS true → publishing must not raise
    scan_tasks._publish("scan-1", {"type": "step", "step": "x"})
    scan_tasks._step("scan-1", "hello")


def test_throttle_disabled_under_fakeredis():
    assert scan_tasks._throttle_enabled() is False


def test_direct_tls_asset_types_route_through_tls_pipeline():
    # mongodb/amqp/grpc are direct-TLS services and mysql is a STARTTLS-upgrade
    # service; run_network_scan selects the protocol as
    # `asset_type if asset_type in _TLS_PROTOCOLS else "https"`, so these must be
    # in the set to reach the DomainScanResult path (not "https").
    for proto in ("mongodb", "amqp", "grpc", "mysql"):
        assert proto in scan_tasks._TLS_PROTOCOLS
    # ssh is handled by its own branch, not the TLS set.
    assert "ssh" not in scan_tasks._TLS_PROTOCOLS


def test_publish_findings_emits_one_message_per_component():
    published = []

    class C:
        def __init__(self, algo, fam, loc, status):
            self.algorithm, self.algorithm_family = algo, fam
            self.location_detail, self.quantum_status = loc, status

    comps = [C("RSA-2048", "RSA", "a:443 (cert)", "vulnerable"),
             C("X25519MLKEM768", "ML-KEM", "a:443 (kex)", "hybrid")]
    with patch.object(scan_tasks, "_publish", lambda sid, p: published.append(p)):
        scan_tasks._publish_findings("scan-1", comps)
    assert [p["type"] for p in published] == ["finding", "finding"]
    assert published[0]["algorithm"] == "RSA-2048"
    assert published[1]["quantum_status"] == "hybrid"


def test_real_broker_publishes_to_scan_channel():
    import json as _json

    fake = fakeredis.FakeStrictRedis()
    ps = fake.pubsub()
    ps.subscribe("scan:scan-42")
    ps.get_message()  # consume the subscribe ack
    with patch.object(scan_tasks, "_real_broker", return_value=True), \
         patch.object(scan_tasks.celery_app.backend, "client", fake):
        scan_tasks._publish("scan-42", {"type": "complete", "components": 3})
    msg = ps.get_message()
    assert msg is not None and msg["type"] == "message"
    payload = _json.loads(msg["data"])
    assert payload == {"type": "complete", "components": 3}


# --- Batch scan endpoint ----------------------------------------------------

async def _register(client, email, org):
    r = await client.post("/api/v1/auth/register", json={
        "email": email, "password": "SecurePass123!", "name": "U", "org_name": org,
    })
    assert r.status_code == 200
    return r.json()["access_token"]


async def _add_asset(client, token, host):
    r = await client.post("/api/v1/assets", json={"type": "domain", "identifier": host},
                          headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text
    return r.json()["id"]


async def test_scan_all_enqueues_one_job_per_asset(client):
    token = await _register(client, "batch@test.com", "Batch Corp")
    for h in ("a.example.com", "b.example.com", "c.example.com"):
        await _add_asset(client, token, h)

    with patch("app.routers.assets.run_network_scan") as mock_scan:
        mock_scan.delay.return_value = MagicMock()
        r = await client.post("/api/v1/assets/scan-all",
                              headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    body = r.json()
    assert body["queued"] == 3
    assert mock_scan.delay.call_count == 3
    assert all(s["status"] == "queued" for s in body["scans"])


async def test_scan_all_empty_org(client):
    token = await _register(client, "empty@test.com", "Empty Corp")
    with patch("app.routers.assets.run_network_scan") as mock_scan:
        mock_scan.delay.return_value = MagicMock()
        r = await client.post("/api/v1/assets/scan-all",
                              headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json() == {"queued": 0, "scans": []}
    mock_scan.delay.assert_not_called()


async def test_scan_all_is_org_scoped(client):
    t1 = await _register(client, "o1@test.com", "Org One")
    t2 = await _register(client, "o2@test.com", "Org Two")
    await _add_asset(client, t1, "one.example.com")
    await _add_asset(client, t2, "two-a.example.com")
    await _add_asset(client, t2, "two-b.example.com")

    with patch("app.routers.assets.run_network_scan") as mock_scan:
        mock_scan.delay.return_value = MagicMock()
        r2 = await client.post("/api/v1/assets/scan-all",
                               headers={"Authorization": f"Bearer {t2}"})
    # org 2 batch only touched org 2's two assets, never org 1's
    assert r2.json()["queued"] == 2
    scanned_hosts = {call.args[3] for call in mock_scan.delay.call_args_list}
    assert scanned_hosts == {"two-a.example.com", "two-b.example.com"}


async def test_scan_all_records_batch_trigger(client):
    token = await _register(client, "trig@test.com", "Trig Corp")
    await _add_asset(client, token, "t.example.com")
    with patch("app.routers.assets.run_network_scan") as mock_scan:
        mock_scan.delay.return_value = MagicMock()
        await client.post("/api/v1/assets/scan-all",
                          headers={"Authorization": f"Bearer {token}"})
    scans = await client.get("/api/v1/scans", headers={"Authorization": f"Bearer {token}"})
    assert any(s["trigger"] == "batch" for s in scans.json())
