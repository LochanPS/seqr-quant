"""Policy enforcement: resolution, evaluation, the guard, and active-policy handling."""
from __future__ import annotations

import json

import pytest

import pqcmap
from pqcmap import (
    CryptoPolicy,
    PolicyViolationError,
    assert_compliant,
    requires_pqc,
    set_active_policy,
)
from pqcmap.policy import (
    DEFAULT_POLICY_BODY,
    compliant,
    family_of,
    get_active_policy,
    load_policy,
    resolve,
    violations,
)


@pytest.fixture(autouse=True)
def _reset_active_policy():
    """Every test starts (and leaves) the process on the default active policy."""
    set_active_policy(None)
    yield
    set_active_policy(None)


# --- resolution -------------------------------------------------------------

@pytest.mark.parametrize(
    "alg,fam",
    [
        ("ML-KEM-768", "ML-KEM"),
        ("ML-DSA-65", "ML-DSA"),
        ("SLH-DSA-SHA2-128f", "SLH-DSA"),
        ("RSA-2048", "RSA"),
        ("ECDSA-P256", "ECDSA"),
        ("X25519", "ECDH"),
        ("Ed25519", "EdDSA"),
        ("something-else", "unknown"),
    ],
)
def test_family_of(alg, fam):
    assert family_of(alg) == fam


def test_resolve_known_uses_metadata():
    r = resolve("ML-KEM-768")
    assert r.family == "ML-KEM" and r.nist_level == 3


def test_resolve_classical_parses_key_size():
    r = resolve("RSA-2048")
    assert r.family == "RSA" and r.nist_level is None and r.key_size == 2048


# --- default policy ---------------------------------------------------------

def test_defaults_pass_under_default_policy():
    # The library's own defaults must be compliant with its own baseline.
    assert compliant("ML-KEM-768", kind="kem")
    assert compliant("ML-DSA-65", kind="sign")
    assert_compliant("ML-KEM-1024", kind="kem")
    assert_compliant("ML-DSA-87", kind="sign")


def test_below_level_blocked():
    for alg in ("ML-KEM-512", "ML-DSA-44"):
        with pytest.raises(PolicyViolationError) as ei:
            assert_compliant(alg)
        assert ei.value.violations[0].rule_key == "min_nist_level_3"
        assert ei.value.algorithm == alg


@pytest.mark.parametrize("alg", ["RSA-2048", "RSA-4096", "ECDSA-P256", "ECDH-P256", "Ed25519"])
def test_quantum_vulnerable_families_blocked(alg):
    with pytest.raises(PolicyViolationError) as ei:
        assert_compliant(alg)
    assert ei.value.violations[0].rule_key == "no_quantum_vulnerable_family"


def test_violations_ranked_most_severe_first():
    # RSA-1024 trips the forbidden-family rule (immediate); severity ordering wins.
    vs = violations("RSA-1024")
    assert vs and vs[0].severity == "immediate"


def test_error_message_names_algorithm_and_target():
    with pytest.raises(PolicyViolationError) as ei:
        assert_compliant("RSA-2048")
    msg = str(ei.value)
    assert "RSA-2048" in msg and "ML-KEM" in msg


# --- custom + spine-shaped policies ----------------------------------------

def test_min_key_size_rule_like_spine_cert():
    body = {
        "name": "cert",
        "rules": [
            {"key": "cert_min_rsa", "slot": "tls:cert", "type": "min_key_size",
             "family": "RSA", "min": 3072, "severity": "planned", "target": "RSA-3072+"},
        ],
    }
    p = CryptoPolicy.from_dict(body)
    assert p.evaluate("RSA-2048", kind="sign")  # 2048 < 3072 -> violation
    assert p.evaluate("RSA-4096", kind="sign") == []


def test_spine_slot_scopes_rule_to_kind():
    # A kex (family_in ML-KEM) rule must not fire on a signature algorithm.
    body = {"rules": [{"key": "kex", "slot": "tls:kex", "type": "family_in",
                       "allowed": ["ML-KEM"], "severity": "urgent", "target": "hybrid"}]}
    p = CryptoPolicy.from_dict(body)
    assert p.evaluate("ML-DSA-65", kind="sign") == []
    assert p.evaluate("RSA-2048", kind="kem")


def test_non_algorithm_rule_types_ignored():
    body = {"rules": [{"key": "origin", "type": "graph_no_origin_edge",
                       "severity": "urgent", "target": "close origin"}]}
    p = CryptoPolicy.from_dict(body)
    assert p.evaluate("RSA-2048") == []  # infra rule doesn't apply to a code algorithm


def test_default_body_ingests_real_spine_baseline():
    # The actual spine DEFAULT_POLICY_BODY must load and evaluate without error.
    from pathlib import Path
    spine = Path(__file__).resolve().parents[2] / "audit/backend/app/spine/policy.py"
    if not spine.exists():
        pytest.skip("spine policy source not present in this checkout")
    text = spine.read_text(encoding="utf-8")
    ns: dict = {}
    # Pull just the DEFAULT_POLICY_BODY literal out of the module without importing it
    # (importing would drag in SQLAlchemy models). Skip if the layout has drifted.
    try:
        start = text.index("DEFAULT_POLICY_BODY = {")
        end = text.index("\n\n", start)
        exec(text[start:end], ns)
        body = ns["DEFAULT_POLICY_BODY"]
    except Exception:  # pragma: no cover - defensive against source drift
        pytest.skip("could not extract spine DEFAULT_POLICY_BODY literal")
    p = CryptoPolicy.from_dict(body)
    # A static-RSA KEX trips the spine's forbidden-RSA kex rule.
    assert p.evaluate("RSA-2048", kind="kem")


def test_invalid_body_rejected():
    with pytest.raises(ValueError):
        CryptoPolicy.from_dict({"nope": []})


# --- policy loading + active policy ----------------------------------------

def test_load_from_file(tmp_path):
    body = {"name": "f", "rules": [{"key": "min", "type": "min_nist_level", "min": 5,
                                    "severity": "urgent", "target": "L5"}]}
    f = tmp_path / "policy.json"
    f.write_text(json.dumps(body), encoding="utf-8")
    p = load_policy(str(f))
    assert p.evaluate("ML-KEM-768", kind="kem")  # level 3 < required 5


def test_env_var_policy(tmp_path, monkeypatch):
    body = {"rules": [{"key": "min5", "type": "min_nist_level", "min": 5,
                       "severity": "urgent", "target": "L5"}]}
    f = tmp_path / "p.json"
    f.write_text(json.dumps(body), encoding="utf-8")
    monkeypatch.setenv("PQCMAP_POLICY", str(f))
    set_active_policy(None)  # re-resolve from env
    with pytest.raises(PolicyViolationError):
        assert_compliant("ML-KEM-768", kind="kem")


def test_set_active_policy_changes_enforcement():
    strict = {"rules": [{"key": "min5", "type": "min_nist_level", "min": 5,
                         "severity": "urgent", "target": "L5"}]}
    set_active_policy(strict)
    assert get_active_policy().evaluate("ML-DSA-65", kind="sign")
    with pytest.raises(PolicyViolationError):
        assert_compliant("ML-DSA-65", kind="sign")
    # ML-DSA-87 (level 5) still passes.
    assert_compliant("ML-DSA-87", kind="sign")


def test_per_call_policy_override():
    strict = {"rules": [{"key": "min5", "type": "min_nist_level", "min": 5,
                         "severity": "urgent", "target": "L5"}]}
    # Active policy is default; the override applies only to this call.
    with pytest.raises(PolicyViolationError):
        assert_compliant("ML-KEM-768", kind="kem", policy=strict)
    assert_compliant("ML-KEM-768", kind="kem")  # default still permits it


# --- guard decorator --------------------------------------------------------

def test_requires_pqc_allows_and_blocks():
    @requires_pqc(kind="sign")
    def mint(algorithm="ML-DSA-65"):
        return algorithm

    assert mint() == "ML-DSA-65"
    assert mint("ML-DSA-87") == "ML-DSA-87"
    with pytest.raises(PolicyViolationError):
        mint("ML-DSA-44")


def test_requires_pqc_positional_and_named_arg():
    @requires_pqc(algorithm_arg="alg", kind="kem")
    def new_key(alg):
        return alg

    assert new_key("ML-KEM-768") == "ML-KEM-768"
    with pytest.raises(PolicyViolationError):
        new_key(alg="ML-KEM-512")


def test_requires_pqc_bare_form():
    @requires_pqc
    def f(algorithm):
        return algorithm

    with pytest.raises(PolicyViolationError):
        f("RSA-2048")


def test_requires_pqc_missing_arg_raises_typeerror():
    @requires_pqc(kind="kem")
    def f(x):  # no 'algorithm' parameter and no default
        return x

    with pytest.raises(TypeError):
        f(1)


def test_public_api_exports():
    for name in ("assert_compliant", "requires_pqc", "CryptoPolicy",
                 "PolicyViolationError", "set_active_policy", "load_policy"):
        assert hasattr(pqcmap, name)
    assert isinstance(DEFAULT_POLICY_BODY, dict)
