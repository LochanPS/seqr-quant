"""Policy-checked constructors in pqcmap.compliant.

They must refuse a below-policy algorithm *before* minting a key, and otherwise behave
exactly like the plain primitives (real FIPS 203/204 crypto)."""
from __future__ import annotations

import pytest

from pqcmap import PolicyViolationError, set_active_policy
from pqcmap.compliant import KeyEncapsulation, Signature


@pytest.fixture(autouse=True)
def _reset_active_policy():
    set_active_policy(None)
    yield
    set_active_policy(None)


def test_compliant_kem_default_roundtrip(pqc_backend):
    kem = KeyEncapsulation()  # ML-KEM-768 — ok under default policy
    kp = kem.generate_keypair()
    ct, ss = kem.encapsulate(kp.public_key)
    assert kem.decapsulate(kp.secret_key, ct) == ss


def test_compliant_sign_default_roundtrip(pqc_backend):
    sig = Signature()  # ML-DSA-65
    kp = sig.generate_keypair()
    s = sig.sign(b"msg", kp.secret_key)
    assert sig.verify(b"msg", s, kp.public_key)


def test_compliant_kem_rejects_below_level():
    with pytest.raises(PolicyViolationError) as ei:
        KeyEncapsulation("ML-KEM-512")
    assert ei.value.violations[0].rule_key == "min_nist_level_3"


def test_compliant_sign_rejects_below_level():
    with pytest.raises(PolicyViolationError):
        Signature("ML-DSA-44")


def test_compliant_kem_rejects_non_kem_algorithm():
    # ML-DSA is a signature family — the kem-scoped forbidden-family rule blocks it.
    with pytest.raises(PolicyViolationError):
        KeyEncapsulation("RSA-2048")


def test_compliant_respects_active_policy():
    # Tighten to Level 5: the Level-3 default now fails at construction.
    set_active_policy({"rules": [{"key": "min5", "type": "min_nist_level", "min": 5,
                                  "severity": "urgent", "target": "L5"}]})
    with pytest.raises(PolicyViolationError):
        KeyEncapsulation("ML-KEM-768")
    KeyEncapsulation("ML-KEM-1024")  # Level 5 — allowed


def test_compliant_per_instance_policy_override(pqc_backend):
    lax = {"rules": []}  # empty policy permits anything
    kem = KeyEncapsulation("ML-KEM-512", policy=lax)  # would fail the default policy
    assert kem.algorithm == "ML-KEM-512"


def test_is_drop_in_subclass():
    from pqcmap.core.kem import KeyEncapsulation as PlainKEM
    from pqcmap.core.sign import Signature as PlainSig

    assert issubclass(KeyEncapsulation, PlainKEM)
    assert issubclass(Signature, PlainSig)
