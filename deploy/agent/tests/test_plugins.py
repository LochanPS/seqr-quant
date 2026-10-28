"""Per-collector tests: cert_store, proxy_conf, pkcs11 stub, tls availability + observation shape."""
import os

from seqr_agent.observation import AssetObservation, classify
from seqr_agent.plugins.cert_store import CertStorePlugin
from seqr_agent.plugins.pkcs11 import PKCS11Plugin
from seqr_agent.plugins.proxy_conf import ProxyConfPlugin
from seqr_agent.plugins.tls_probe import TLSProbePlugin

from _certs import ec_der, rsa_pem


# ------------------------------------------------------------------ observation
def test_classify_infers_family_and_status():
    assert classify("RSA-2048")[1] == "vulnerable"
    assert classify("ML-KEM-768")[1] == "safe"
    assert classify("X25519MLKEM768")[1] == "hybrid"
    assert classify("weirdalgo")[1] == "unknown"


def test_observation_to_dict_drops_nones_and_autoclassifies():
    o = AssetObservation(asset_key="h", location_type="tls_cert", algorithm="RSA-4096")
    d = o.to_dict()
    assert d["algorithm_family"] == "RSA"
    assert d["quantum_status"] == "vulnerable"
    assert "cert_issuer" not in d  # None dropped


# ------------------------------------------------------------------ cert_store
def test_cert_store_reads_pem_and_der(tmp_path):
    (tmp_path / "rsa.pem").write_bytes(rsa_pem(cn="rsa-a.internal"))
    (tmp_path / "ec.der").write_bytes(ec_der(cn="ec-b.internal"))
    plugin = CertStorePlugin(config={"paths": [str(tmp_path)]})
    assert plugin.available() is True
    obs = {o.algorithm: o for o in plugin.collect()}
    assert "RSA" in obs and obs["RSA"].key_size == 2048
    assert "ECDSA" in obs and obs["ECDSA"].key_size == 256
    assert all(o.location_type == "cert_store" for o in plugin.collect())


def test_cert_store_dedupes_identical_certs(tmp_path):
    pem = rsa_pem(cn="dup.internal")
    (tmp_path / "a.pem").write_bytes(pem)
    (tmp_path / "b.pem").write_bytes(pem)  # same bytes twice
    plugin = CertStorePlugin(config={"paths": [str(tmp_path)]})
    assert len(plugin.collect()) == 1


def test_cert_store_unavailable_without_paths_or_trust():
    assert CertStorePlugin(config={}).available() is False


def test_cert_store_os_trust_available_flag():
    # Enumerating the OS store should not raise and should mark available.
    p = CertStorePlugin(config={"include_os_trust": True})
    assert p.available() is True
    _ = p.collect()  # may be empty on a bare CI box, but must not raise


# ------------------------------------------------------------------ proxy_conf
_NGINX = """
server {
    server_name lb.internal;   # edge
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ecdh_curve X25519:prime256v1;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384;
    ssl_certificate /etc/nginx/ssl/site.pem;
}
"""

_HAPROXY = """
frontend fe
    bind :443 ssl crt /etc/haproxy/site.pem ciphers ECDHE-RSA-AES128-GCM-SHA256 curves secp384r1
    ssl-default-bind-curves X25519
"""


def test_proxy_conf_parses_nginx(tmp_path):
    f = tmp_path / "site.conf"
    f.write_text(_NGINX)
    obs = ProxyConfPlugin(config={"nginx": [str(f)]}).collect()
    cfgs = [o for o in obs if o.location_type == "tls_config"]
    assert cfgs and cfgs[0].asset_key == "lb.internal"
    assert cfgs[0].algorithm == "X25519:prime256v1"  # ecdh curve is the kex signal
    assert "protocols=TLSv1.2 TLSv1.3" in cfgs[0].location_detail


def test_proxy_conf_parses_haproxy_bind(tmp_path):
    f = tmp_path / "haproxy.cfg"
    f.write_text(_HAPROXY)
    obs = ProxyConfPlugin(config={"haproxy": [str(f)]}).collect()
    binds = [o for o in obs if o.location_type == "tls_config"]
    assert binds and binds[0].asset_type == "reverse_proxy"
    assert binds[0].algorithm == "secp384r1"


def test_proxy_conf_parses_referenced_cert(tmp_path):
    (tmp_path / "site.pem").write_bytes(rsa_pem(cn="proxied.internal"))
    conf = tmp_path / "n.conf"
    conf.write_text(f"""
server {{
  server_name p.internal;
  ssl_certificate {tmp_path / 'site.pem'};
}}
""")
    obs = ProxyConfPlugin(config={"nginx": [str(conf)]}).collect()
    certs = [o for o in obs if o.location_type == "cert_store"]
    assert certs and certs[0].algorithm == "RSA"


def test_proxy_conf_unavailable_without_targets():
    assert ProxyConfPlugin(config={}).available() is False


# ------------------------------------------------------------------ pkcs11 stub
def _fake_hsm(_config):
    return [{
        "slot_id": 0, "token": "prod-token",
        "mechanisms": ["CKM_RSA_PKCS", "CKM_EC_KEY_PAIR_GEN"],
        "public_keys": [
            {"key_type": "CKK_RSA", "label": "signing-key", "id": "01", "bits": 2048},
            {"key_type": "CKK_EC", "label": "tls-key", "id": "02", "bits": 256},
        ],
    }, {
        "slot_id": 1, "token": "pqc-token",
        "mechanisms": ["CKM_ML_KEM"], "public_keys": [],  # login-gated: mechanisms only
    }]


def test_pkcs11_stub_enumerates_public_keys():
    p = PKCS11Plugin(config={"_enumerator": _fake_hsm})
    assert p.available() is True
    obs = p.collect()
    keys = {o.algorithm: o for o in obs if o.location_type == "hsm_key"}
    assert keys["RSA"].key_size == 2048 and keys["RSA"].asset_type == "hsm_key"
    assert keys["ECDSA"].key_size == 256
    tokens = [o for o in obs if o.location_type == "hsm_token"]
    assert tokens and tokens[0].algorithm == "ML-KEM"  # mechanism-only token


def test_pkcs11_never_extracts_key_material():
    # The stub emits no field that could carry private key bytes.
    obs = PKCS11Plugin(config={"_enumerator": _fake_hsm}).collect()
    for o in obs:
        d = o.to_dict()
        assert not any("private" in str(v).lower() for v in d.values())
        assert set(d).issubset({
            "asset_key", "asset_key_type", "asset_type", "asset_name", "location_type",
            "location_detail", "algorithm", "algorithm_family", "key_size", "quantum_status",
            "confidence", "observed_at", "cert_expiry_date", "cert_issuer", "plugin",
        })


def test_pkcs11_unavailable_without_module_or_enumerator():
    assert PKCS11Plugin(config={}).available() is False
    assert PKCS11Plugin(config={"module": "/no/such/module.so"}).available() is False


# ------------------------------------------------------------------ tls
def test_tls_available_only_with_targets():
    assert TLSProbePlugin(config={}).available() is False
    assert TLSProbePlugin(config={"targets": [{"host": "x", "port": 443}]}).available() is True
