"""Declarative crypto-policy evaluation (reuses the spine `{"rules":[...]}` shape)."""
import json
from dataclasses import dataclass

import pytest

from seqr.ci.policy import (
    CryptoPolicy,
    DEFAULT_POLICY_BODY,
    evaluate_findings,
    find_policy_file,
    load_policy,
)


@dataclass
class F:
    algorithm: str = "RSA-2048"
    algorithm_family: str = "RSA"
    pattern_id: str = "py.rsa.keygen"
    file_path: str = "src/a.py"
    line_number: int = 1
    code_snippet: str = "rsa.generate_private_key()"


# -- default policy -----------------------------------------------------------

def test_default_forbids_quantum_vulnerable_families():
    pol = CryptoPolicy.default()
    assert pol.evaluate_finding(F(algorithm="RSA-2048", algorithm_family="RSA"))
    assert pol.evaluate_finding(F(algorithm="ECDSA-SHA256", algorithm_family="ECC"))
    assert pol.evaluate_finding(F(algorithm="DH", algorithm_family="DH"))


def test_default_passes_pqc_family():
    pol = CryptoPolicy.default()
    assert pol.evaluate_finding(F(algorithm="ML-KEM-768", algorithm_family="ML-KEM")) == []


def test_violation_message_names_algorithm_and_target():
    v = CryptoPolicy.default().evaluate_finding(F(algorithm="RSA-2048", algorithm_family="RSA"))[0]
    assert v.rule_key == "no_quantum_vulnerable_family"
    assert "RSA-2048" in v.actual
    assert "ML-KEM" in v.target


# -- rule vocabulary (spine shape) -------------------------------------------

def test_min_key_size_rule_tolerates_strong_rsa():
    body = {
        "name": "rsa-3072-min",
        "rules": [
            {"key": "cert_min_rsa", "type": "min_key_size", "family": "RSA", "min": 3072,
             "severity": "planned", "target": "RSA-3072+"},
        ],
    }
    pol = CryptoPolicy.from_dict(body)
    assert pol.evaluate_finding(F(algorithm="RSA-2048", algorithm_family="RSA"))      # too small
    assert pol.evaluate_finding(F(algorithm="RSA-4096", algorithm_family="RSA")) == []  # ok


def test_family_in_requires_allowed_family():
    body = {"name": "pqc-only", "rules": [
        {"key": "must_be_mlkem", "type": "family_in", "allowed": ["ML-KEM"],
         "severity": "urgent", "target": "ML-KEM-768"},
    ]}
    pol = CryptoPolicy.from_dict(body)
    assert pol.evaluate_finding(F(algorithm="RSA-2048", algorithm_family="RSA"))
    assert pol.evaluate_finding(F(algorithm="ML-KEM-768", algorithm_family="ML-KEM")) == []


def test_spine_graph_and_slot_rules_are_ignored_for_code():
    # A full spine DEFAULT_POLICY_BODY-style body: graph + slot rules must not fire here,
    # but the module must still ingest the shape without error.
    body = {"name": "spine", "rules": [
        {"key": "no_exposed_classical_origin", "type": "graph_no_origin_edge",
         "severity": "urgent", "target": "close origin"},
        {"key": "kex_must_be_hybrid", "slot": "tls:kex", "type": "family_in",
         "allowed": ["ML-KEM"], "severity": "urgent", "target": "X25519MLKEM768"},
    ]}
    pol = CryptoPolicy.from_dict(body)
    # The graph rule is skipped; the slot family_in rule still evaluates on family, and an
    # RSA finding is not ML-KEM, so it drifts — but no crash on the graph rule.
    vs = pol.evaluate_finding(F(algorithm="RSA-2048", algorithm_family="RSA"))
    assert all(v.rule_key != "no_exposed_classical_origin" for v in vs)


# -- loading ------------------------------------------------------------------

def test_load_default_when_no_file(tmp_path):
    pol = load_policy(root=tmp_path)
    assert pol.name == DEFAULT_POLICY_BODY["name"]


def test_load_discovers_seqr_policy_json(tmp_path):
    body = {"name": "mine", "rules": []}
    (tmp_path / "seqr-policy.json").write_text(json.dumps(body), encoding="utf-8")
    assert find_policy_file(tmp_path) is not None
    assert load_policy(root=tmp_path).name == "mine"


def test_bad_body_raises():
    with pytest.raises(ValueError):
        CryptoPolicy.from_dict({"no_rules": True})


# -- evaluate_findings map ----------------------------------------------------

def test_evaluate_findings_keys_by_identity():
    findings = [F(algorithm="RSA-2048", algorithm_family="RSA"),
                F(algorithm="ML-KEM-768", algorithm_family="ML-KEM")]
    drift = evaluate_findings(CryptoPolicy.default(), findings)
    assert id(findings[0]) in drift
    assert id(findings[1]) not in drift
