"""T7 collectors — ssh, k8s, cloud(ACM). Fixture-injected: no live k8s/cloud/SSH is hit.

Each collector takes an injected client/scanner (the same pattern pkcs11 uses for `_enumerator`)
so these tests drive the real normalize/emit path against recorded shapes, never the network.
"""
from seqr_agent.observation import AssetObservation
from seqr_agent.plugins import REGISTRY
from seqr_agent.plugins.cloud import CloudPlugin, _parse_key_algorithm
from seqr_agent.plugins.k8s import K8sPlugin
from seqr_agent.plugins.ssh_probe import SSHProbePlugin, _hostkey_family

from _certs import rsa_pem


# ================================================================= registry
def test_registry_exposes_t7_collectors():
    for k in ("ssh", "k8s", "cloud"):
        assert k in REGISTRY


# ================================================================= ssh
def _ssh_result(**over):
    base = {
        "reachable": True,
        "server_banner": "SSH-2.0-OpenSSH_9.6",
        "kex_algorithms": ["curve25519-sha256", "ecdh-sha2-nistp256"],
        "host_key_algorithms": ["ssh-ed25519", "rsa-sha2-512"],
        "pqc_kex_methods": [],
        "pqc_kex_supported": False,
        "host_key_quantum_status": "vulnerable",
    }
    base.update(over)
    return base


def test_ssh_unavailable_without_targets():
    assert SSHProbePlugin(config={}).available() is False


def test_ssh_available_with_scanner_and_targets():
    p = SSHProbePlugin(config={"targets": [{"host": "h", "port": 22}], "_scanner": lambda h, port: {}})
    assert p.available() is True


def test_ssh_classical_endpoint():
    p = SSHProbePlugin(config={
        "targets": [{"host": "bastion.internal", "port": 22, "role": "bastion"}],
        "_scanner": lambda h, port: _ssh_result(),
    })
    obs = {o.location_type: o for o in p.collect()}
    kex = obs["ssh_kex"]
    assert kex.algorithm == "curve25519-sha256"
    assert kex.quantum_status == "vulnerable"
    hk = obs["ssh_hostkey"]
    assert hk.algorithm == "ssh-ed25519" and hk.algorithm_family == "ECC"
    assert hk.quantum_status == "vulnerable"


def test_ssh_pqc_endpoint_upgrades_kex_status():
    p = SSHProbePlugin(config={
        "targets": [{"host": "gw.internal", "port": 22}],
        "_scanner": lambda h, port: _ssh_result(
            kex_algorithms=["mlkem768x25519-sha256", "curve25519-sha256"],
            pqc_kex_methods=["mlkem768x25519-sha256"], pqc_kex_supported=True),
    })
    kex = [o for o in p.collect() if o.location_type == "ssh_kex"][0]
    assert kex.algorithm == "mlkem768x25519-sha256"
    assert kex.quantum_status == "hybrid"
    assert kex.algorithm_family == "ML-KEM"


def test_ssh_unreachable_target_emits_nothing():
    p = SSHProbePlugin(config={
        "targets": [{"host": "dead", "port": 22}],
        "_scanner": lambda h, port: _ssh_result(reachable=False),
    })
    assert p.collect() == []


def test_ssh_scanner_exception_does_not_abort():
    def boom(h, port):
        raise RuntimeError("connection refused")
    p = SSHProbePlugin(config={"targets": [{"host": "x", "port": 22}], "_scanner": boom})
    assert p.collect() == []


def test_ssh_hostkey_family_mapping():
    assert _hostkey_family("rsa-sha2-256") == "RSA"
    assert _hostkey_family("ecdsa-sha2-nistp384") == "ECC"
    assert _hostkey_family("ssh-ed25519") == "ECC"


# ================================================================= k8s
def _k8s_client(_config):
    return {
        "tls_secrets": [
            {"namespace": "prod", "name": "web-tls", "cert_pem": rsa_pem(cn="web.prod.svc")},
        ],
        "certificates": [
            {"namespace": "prod", "name": "api-cert", "dns_names": ["api.prod.example"],
             "key_algorithm": "ECDSA", "key_size": 384},
        ],
        "ingresses": [
            {"namespace": "prod", "name": "web-ingress", "hosts": ["web.example"],
             "secret_name": "web-tls"},
        ],
    }


def test_k8s_available_with_injected_client():
    assert K8sPlugin(config={"_client": _k8s_client}).available() is True


def test_k8s_tls_secret_parsed_from_public_leaf():
    obs = K8sPlugin(config={"_client": _k8s_client}).collect()
    secrets = [o for o in obs if o.location_type == "k8s_tls_secret"]
    assert secrets and secrets[0].algorithm == "RSA" and secrets[0].key_size == 2048
    assert secrets[0].asset_key == "k8s:prod/web-tls"
    assert secrets[0].quantum_status == "vulnerable"


def test_k8s_cert_manager_records_declared_key():
    obs = K8sPlugin(config={"_client": _k8s_client}).collect()
    cm = [o for o in obs if o.location_type == "k8s_cert_manager"]
    assert cm and cm[0].algorithm == "ECDSA" and cm[0].algorithm_family == "ECC"
    assert cm[0].key_size == 384 and cm[0].confidence == "medium"


def test_k8s_ingress_points_at_secret():
    obs = K8sPlugin(config={"_client": _k8s_client}).collect()
    ing = [o for o in obs if o.location_type == "k8s_ingress"]
    assert ing and "web-tls" in ing[0].location_detail
    assert ing[0].algorithm == "tls-terminated"


def test_k8s_toggles_disable_sources():
    obs = K8sPlugin(config={"_client": _k8s_client,
                            "include_cert_manager": False,
                            "include_ingress": False}).collect()
    assert {o.location_type for o in obs} == {"k8s_tls_secret"}


def test_k8s_never_reads_private_key():
    # A tls secret carrying a tls.key must never surface any private material.
    def client(_c):
        return {"tls_secrets": [{"namespace": "prod", "name": "web-tls",
                                 "cert_pem": rsa_pem(), "tls.key": "PRIVATE-KEY-BYTES"}]}
    obs = K8sPlugin(config={"_client": client}).collect()
    for o in obs:
        for v in o.to_dict().values():
            assert "private" not in str(v).lower()


def test_k8s_client_exception_yields_empty():
    def boom(_c):
        raise RuntimeError("403 forbidden")
    assert K8sPlugin(config={"_client": boom}).collect() == []


# ================================================================= cloud (AWS ACM)
def _acm_client(_config):
    return [
        {"arn": "arn:aws:acm:ap-south-1:1:certificate/a", "domain_name": "www.example.in",
         "key_algorithm": "RSA-2048", "issuer": "Amazon", "not_after": "2027-01-01",
         "in_use": True, "status": "ISSUED"},
        {"arn": "arn:aws:acm:ap-south-1:1:certificate/b", "domain_name": "api.example.in",
         "key_algorithm": "EC-prime256v1", "issuer": "Amazon", "not_after": "2027-06-01",
         "in_use": False, "status": "ISSUED"},
    ]


def test_cloud_available_with_injected_client():
    assert CloudPlugin(config={"_client": _acm_client}).available() is True


def test_cloud_unavailable_for_unwired_provider_without_client():
    assert CloudPlugin(config={"provider": "azure"}).available() is False


def test_cloud_acm_certs_normalized():
    obs = {o.asset_key: o for o in CloudPlugin(config={"provider": "aws", "_client": _acm_client}).collect()}
    rsa = obs["www.example.in"]
    assert rsa.algorithm == "RSA" and rsa.key_size == 2048
    assert rsa.location_type == "cloud_acm" and rsa.quantum_status == "vulnerable"
    assert "in-use" in rsa.location_detail
    ec = obs["api.example.in"]
    assert ec.algorithm == "ECDSA" and ec.algorithm_family == "ECC" and ec.key_size == 256


def test_cloud_client_exception_yields_empty():
    def boom(_c):
        raise RuntimeError("NoCredentialsError")
    assert CloudPlugin(config={"provider": "aws", "_client": boom}).collect() == []


def test_parse_key_algorithm_variants():
    assert _parse_key_algorithm("RSA-4096") == ("RSA", "RSA", 4096)
    assert _parse_key_algorithm("EC-secp384r1") == ("ECDSA", "ECC", 384)
    assert _parse_key_algorithm("EC-secp521r1") == ("ECDSA", "ECC", 521)
    assert _parse_key_algorithm(None)[0] == "unknown"


def test_cloud_observations_carry_no_key_material():
    obs = CloudPlugin(config={"provider": "aws", "_client": _acm_client}).collect()
    for o in obs:
        d = o.to_dict()
        assert not any("private" in str(v).lower() for v in d.values())
