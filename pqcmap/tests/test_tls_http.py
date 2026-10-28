"""pqcmap.tls.http — httpx / requests clients wired to the PQC-hybrid TLS context."""
import ssl

import pytest

from pqcmap.tls import http as pqc_http
from pqcmap.tls.context import TLSCapabilities


def test_httpx_client_uses_pqc_context():
    httpx = pytest.importorskip("httpx")
    with pqc_http.pqc_httpx_client() as client:
        assert isinstance(client, httpx.Client)
        assert isinstance(client.pqc_capabilities, TLSCapabilities)


def test_requests_session_mounts_pqc_adapter():
    pytest.importorskip("requests")
    session = pqc_http.pqc_requests_session()
    try:
        adapter = session.get_adapter("https://example.com")
        # the mounted adapter carries our SSLContext into the pool manager
        assert adapter is session.get_adapter("https://anything.example")
        assert isinstance(session.pqc_capabilities, TLSCapabilities)
    finally:
        session.close()


def test_requests_adapter_injects_ssl_context():
    pytest.importorskip("requests")
    ctx, _ = __import__(
        "pqcmap.tls.context", fromlist=["build_client_context"]
    ).build_client_context()
    adapter = pqc_http.PQCTLSAdapter(ctx)
    pm = adapter.poolmanager
    assert pm.connection_pool_kw.get("ssl_context") is ctx


def test_module_capabilities_reexport():
    caps = pqc_http.capabilities()
    assert isinstance(caps, TLSCapabilities)


def test_verify_false_context_flows_through_to_httpx():
    pytest.importorskip("httpx")
    with pqc_http.pqc_httpx_client(verify=False) as client:
        assert client.pqc_capabilities.openssl_version.startswith("OpenSSL")
