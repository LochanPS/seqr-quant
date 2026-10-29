"""Tests for the context-aware risk engine (engines/risk_v2.py)."""

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from engines.risk_v2 import (CONTROL_FLOOR, RiskContext, assess_finding, assess_findings,
                             infer_role, summarize, tier_for)

SAMPLE = Path(__file__).resolve().parents[2] / "ecdat-demo" / "sample-repo"


@dataclass
class F:
    file_path: str
    algorithm: str = "RSA"
    algorithm_family: str = "RSA"
    algorithm_risk: int = 8
    quantum_status: str = "vulnerable"
    confidence: str = "high"
    line_number: int = 1
    code_snippet: str = ""
    matched_function: str = ""
    matched_string: str = ""
    matched_import: str = ""
    recommended_replacement: str = ""


# ── role inference ──

@pytest.mark.parametrize("finding,role", [
    (F("x.py", "DH", "DH", code_snippet="dh.generate_parameters(generator=2)"), "key_exchange"),
    (F("x.js", code_snippet="publicKey.encrypt(buf, 'RSA-OAEP')"), "encryption"),
    (F("x.go", "ECDSA", "ECC", code_snippet="ecdsa.GenerateKey(elliptic.P256())"), "signature"),
    (F("x.py", "RSA-SHA256", code_snippet="jwt.encode(p, k, algorithm='RS256')"), "signature"),
    (F("x.java", code_snippet='KeyPairGenerator.getInstance("RSA")'), "keygen"),
    (F("x.py", "SHA1", "SHA", code_snippet="hashlib.sha1(b)"), "hash"),
])
def test_infer_role(finding, role):
    assert infer_role(finding) == role


# ── path inference ──

def test_test_code_is_heavily_discounted(tmp_path):
    prod = assess_finding(F(str(tmp_path / "api" / "keys.py")), tmp_path)
    test = assess_finding(F(str(tmp_path / "tests" / "test_keys.py")), tmp_path)
    assert test.code_reality == "test"
    assert test.score < prod.score * 0.2


@pytest.mark.parametrize("rel,reality", [
    ("vendor/lib/rsa.py", "vendored"),
    ("node_modules/forge/rsa.js", "vendored"),
    ("examples/demo.py", "example"),
    ("src/auth.spec.ts", "test"),
    ("src/auth.py", "production"),
])
def test_code_reality_inference(tmp_path, rel, reality):
    assert assess_finding(F(str(tmp_path / rel)), tmp_path).code_reality == reality


def test_exposure_and_data_inference(tmp_path):
    a = assess_finding(F(str(tmp_path / "gateway" / "payments.go")), tmp_path)
    assert a.exposure == "internet"
    assert (a.data_sensitivity, a.shelf_life) == ("confidential", "long")
    b = assess_finding(F(str(tmp_path / "metrics" / "ticker.py")), tmp_path)
    assert (b.data_sensitivity, b.shelf_life) == ("public", "short")
    c = assess_finding(F(str(tmp_path / "misc" / "thing.py")), tmp_path)
    assert c.exposure == "unknown" and "exposure" in c.inferred


# ── scoring ──

def test_safe_algorithm_scores_zero(tmp_path):
    a = assess_finding(F(str(tmp_path / "api" / "k.py"), "ML-KEM-768", "ML-KEM", 0, "safe"), tmp_path)
    assert a.score == 0 and a.tier == "MONITOR"


def test_internet_key_exchange_outranks_internal_signature(tmp_path):
    kex = assess_finding(F(str(tmp_path / "api" / "payments.py"), "DH", "DH",
                           code_snippet="dh.generate_parameters()"), tmp_path)
    sig = assess_finding(F(str(tmp_path / "internal" / "tokens.py"),
                           code_snippet="jwt.encode(p, k, algorithm='RS256')"), tmp_path)
    assert kex.score > sig.score * 2


def test_hndl_requires_visible_confidentiality_use(tmp_path):
    ctx = RiskContext(rules=[{"match": "*", "exposure": "internet", "shelf_life": "long"}])
    kex = assess_finding(F(str(tmp_path / "a.py"), "DH", "DH", code_snippet="dh.exchange(pk)"), tmp_path, ctx)
    keygen = assess_finding(F(str(tmp_path / "b.py"), code_snippet="RSA.generate(2048)"), tmp_path, ctx)
    sig = assess_finding(F(str(tmp_path / "c.py"), code_snippet="key.sign(m)"), tmp_path, ctx)
    assert kex.hndl is True
    assert keygen.hndl is False   # role not visible at the line -> no boost
    assert sig.hndl is False      # signatures are not harvest-now-decrypt-later


def test_hndl_not_for_short_lived_data(tmp_path):
    ctx = RiskContext(rules=[{"match": "*", "exposure": "internet", "shelf_life": "short"}])
    a = assess_finding(F(str(tmp_path / "a.py"), "DH", "DH", code_snippet="dh.exchange(pk)"), tmp_path, ctx)
    assert a.hndl is False


def test_controls_reduce_with_floor(tmp_path):
    base = assess_finding(F(str(tmp_path / "api" / "k.py")), tmp_path)
    one = assess_finding(F(str(tmp_path / "api" / "k.py")), tmp_path,
                         RiskContext(rules=[{"match": "*", "controls": ["mtls"]}]))
    many = assess_finding(F(str(tmp_path / "api" / "k.py")), tmp_path,
                          RiskContext(rules=[{"match": "*", "controls": ["a", "b", "c", "d", "e", "f"]}]))
    assert one.score < base.score
    assert many.score == pytest.approx(base.score * CONTROL_FLOOR, abs=0.2)


def test_blast_radius_boost_is_capped(tmp_path):
    base = assess_finding(F(str(tmp_path / "svc" / "k.py")), tmp_path)
    wide = assess_finding(F(str(tmp_path / "svc" / "k.py")), tmp_path,
                          RiskContext(rules=[{"match": "*", "dependents": 10_000}]))
    assert base.score < wide.score <= base.score * 1.5 + 0.1


def test_every_moving_factor_has_a_reason(tmp_path):
    a = assess_finding(F(str(tmp_path / "tests" / "test_x.py"), code_snippet="encrypt(x)"), tmp_path)
    assert all(f.reason for f in a.factors)
    assert a.top_reason


@pytest.mark.parametrize("score,tier", [(96, "IMMEDIATE"), (70, "IMMEDIATE"), (69.9, "URGENT"),
                                        (45, "URGENT"), (20, "PLANNED"), (19.9, "MONITOR"), (0, "MONITOR")])
def test_tiers(score, tier):
    assert tier_for(score) == tier


# ── context file ──

def test_context_overrides_and_marks_supplied(tmp_path):
    ctx = RiskContext(rules=[{"match": "payments/*", "exposure": "internet",
                              "data_sensitivity": "highly_confidential", "shelf_life": "long"}])
    a = assess_finding(F(str(tmp_path / "payments" / "dh.py"), "DH", "DH"), tmp_path, ctx)
    assert a.exposure == "internet" and a.data_sensitivity == "highly_confidential"
    assert "exposure" not in a.inferred and "shelf_life" not in a.inferred


def test_context_load_validates(tmp_path):
    good = tmp_path / "ctx.json"
    good.write_text(json.dumps({"rules": [{"match": "a/*", "exposure": "internal", "note": "x"}]}))
    assert RiskContext.load(good).rules
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"rules": [{"exposure": "internal"}]}))
    with pytest.raises(ValueError):
        RiskContext.load(bad)
    typo = tmp_path / "typo.json"
    typo.write_text(json.dumps({"rules": [{"match": "*", "exposur": "internal"}]}))
    with pytest.raises(ValueError):
        RiskContext.load(typo)


def test_duplicates_collapse(tmp_path):
    p = str(tmp_path / "api" / "k.js")
    r = assess_findings([F(p, line_number=3, confidence="medium"), F(p, line_number=3), F(p, line_number=9)], tmp_path)
    assert len(r) == 2
    assert max(a.duplicates for a in r) == 1


# ── end to end on the labelled ACME sample ──

@pytest.mark.skipif(not SAMPLE.exists(), reason="ecdat-demo sample repo not present")
def test_acme_sample_is_no_longer_flat():
    from scanner.code import CodeScanner
    findings = CodeScanner().scan_directory(str(SAMPLE))
    r = assess_findings(findings, SAMPLE)
    tiers = {t for t, n in summarize(r)["tiers"].items() if n}
    assert len(tiers) >= 2                 # v1 put every finding in one bucket
    assert len(r) < len(findings)          # duplicate matches collapsed
    assert r == sorted(r, key=lambda a: -a.score)

    ctx = RiskContext(rules=[{"match": "payments/*", "exposure": "internet",
                              "data_sensitivity": "highly_confidential", "shelf_life": "long"}])
    top = assess_findings(findings, SAMPLE, ctx)[0]
    assert top.rel_path == "payments/legacy_dh.py" and top.hndl and top.tier == "IMMEDIATE"


# ── infrastructure components ──

from engines.risk_v2 import InfraComponent, assess_component, assess_components, infra_algorithm_risk  # noqa: E402


def C(**kw):
    base = dict(asset_id="a1", asset_identifier="api.bank.example", asset_type="domain",
                slot_key="tls:kex", algorithm="X25519", algorithm_family="ECC",
                quantum_status="vulnerable", data_sensitivity="confidential")
    base.update(kw)
    return InfraComponent(**base)


def test_hybrid_kex_scores_zero():
    a = assess_component(C(algorithm="X25519MLKEM768", algorithm_family="ML-KEM", quantum_status="hybrid"))
    assert a.score == 0 and a.tier == "MONITOR"


def test_public_kex_on_long_lived_data_is_hndl():
    a = assess_component(C(asset_identifier="kyc.bank.example"))
    assert a.role == "key_exchange" and a.exposure == "internet"
    assert a.hndl is True and a.tier in {"IMMEDIATE", "URGENT"}


def test_certificate_is_signature_and_not_hndl():
    a = assess_component(C(slot_key="tls:cert", algorithm="RSA-2048", algorithm_family="RSA", key_size=2048))
    assert a.role == "signature" and a.hndl is False
    kex = assess_component(C())
    assert a.score < kex.score


def test_internal_host_ranks_below_public_endpoint():
    public = assess_component(C())
    internal = assess_component(C(asset_type="host", asset_identifier="app01.internal"))
    assert internal.exposure == "internal" and internal.score < public.score


def test_origin_behind_edge_gets_bypass_reason():
    a = assess_component(C(asset_type="origin", asset_identifier="origin-api.bank.example", fronted_by_edge=True))
    assert a.exposure == "internet"
    assert any("route around edge" in f.reason for f in a.factors)


def test_dependents_raise_blast_radius():
    # unsaturated case (cert on internal data) so the 100 cap can't mask the effect
    kw = dict(asset_type="load_balancer", slot_key="tls:cert", data_sensitivity="internal",
              algorithm="RSA-2048", algorithm_family="RSA", key_size=2048)
    one = assess_component(C(dependents=1, **kw))
    many = assess_component(C(dependents=8, **kw))
    assert one.score < 100 and many.score > one.score


def test_infra_algorithm_risk_table():
    assert infra_algorithm_risk("RSA", "RSA-1024", 1024, "vulnerable") == 10
    assert infra_algorithm_risk("RSA", "RSA-2048", 2048, "vulnerable") == 8
    assert infra_algorithm_risk("ECC", "X25519", None, "vulnerable") == 8
    assert infra_algorithm_risk("ML-KEM", "X25519MLKEM768", None, "hybrid") == 0


def test_components_ranked_descending():
    r = assess_components([C(asset_type="host"), C(asset_identifier="kyc.bank.example"),
                           C(quantum_status="hybrid", algorithm="X25519MLKEM768")])
    assert [a.score for a in r] == sorted((a.score for a in r), reverse=True)
    assert r[-1].score == 0


@pytest.mark.parametrize("atype,exposure", [
    ("tls_endpoint", "internet"), ("domain", "internet"), ("smtp", "internet"),
    ("postgres", "internal"), ("ssh", "internal"), ("hsm", "at_rest"), ("weird_thing", "unknown"),
])
def test_every_asset_type_maps_and_is_marked_inferred(atype, exposure):
    a = assess_component(C(asset_type=atype))
    assert a.exposure == exposure
    assert "exposure" in a.inferred
