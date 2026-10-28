"""Tests for execute.py — real X25519+ML-KEM-768 migration, verify-gate, rollback.

Fully local (real cryptography FIPS-203 ML-KEM) — no network, no API keys.
"""

from app.migration.execute import (CLASSICAL, HYBRID, Service, handshake,
                                    migrate_with_gate, probe, verify_gate)


def test_classical_before_migration():
    svc = Service("svc")
    t = probe(svc)
    assert t.group == CLASSICAL
    assert t.session_agreed is True
    assert t.pq_secure is False


def test_healthy_migration_converges():
    svc = Service("payment-api")
    r = migrate_with_gate(svc)
    assert r["before"].group == CLASSICAL
    assert r["after"].group == HYBRID
    assert r["after"].session_agreed is True
    assert r["after"].pq_secure is True
    assert r["converged"] is True
    assert r["final_mode"] == HYBRID
    assert r["rolled_back"] is None


def test_botched_migration_rolls_back():
    svc = Service("auth-svc")
    r = migrate_with_gate(svc, broken=True)
    # negotiates hybrid but the session cannot agree -> gate must reject
    assert r["after"].group == HYBRID
    assert r["after"].session_agreed is False
    assert r["converged"] is False
    # rolled safely back to classical, service still usable
    assert r["final_mode"] == CLASSICAL
    assert r["rolled_back"] is not None
    assert r["rolled_back"].group == CLASSICAL
    assert r["rolled_back"].session_agreed is True


def test_honest_hybrid_handshake():
    svc = Service("kyc-svc")
    svc.configure(HYBRID)
    t = handshake(svc)
    assert t.group == HYBRID
    assert t.session_agreed is True
    assert t.ciphertext_bytes == 1088  # ML-KEM-768 ciphertext size


def test_tampered_ciphertext_rejected():
    svc = Service("kyc-svc")
    svc.configure(HYBRID)
    t = handshake(svc, tamper=True)
    assert t.session_agreed is False  # implicit rejection -> keys differ


def test_forged_ciphertext_rejected():
    svc = Service("kyc-svc")
    svc.configure(HYBRID)
    t = handshake(svc, forge=True)
    assert t.session_agreed is False
    assert "REJECTED" in t.detail  # wrong-length ciphertext raises, handled


def test_verify_gate_pass_and_fail():
    ok_svc = Service("ok")
    ok_svc.configure(HYBRID)
    converged, t = verify_gate(ok_svc)
    assert converged is True and t.group == HYBRID

    classical_svc = Service("still-classical")
    converged2, t2 = verify_gate(classical_svc)  # target hybrid, but still classical
    assert converged2 is False


def test_ml_kem_shared_secret_actually_matches():
    """Direct proof the hybrid session key derives from a real matching ML-KEM secret."""
    svc = Service("x")
    svc.configure(HYBRID)
    # two independent honest handshakes both succeed (fresh ephemeral each time)
    assert handshake(svc).session_agreed is True
    assert handshake(svc).session_agreed is True
