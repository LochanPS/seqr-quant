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
