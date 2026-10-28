"""PyJWT-shaped adapter — drop-in encode/decode, algorithm allow-list, exceptions."""
import time

import pytest

import pqcmap.jwt as jwt
from pqcmap import Signature
from pqcmap.algorithms import SignAlgorithm
from pqcmap.core.exceptions import PQCError


def _keypair(pqc_backend):
    return Signature().generate_keypair()


def test_encode_decode_roundtrip(pqc_backend):
    kp = _keypair(pqc_backend)
    token = jwt.encode({"sub": "alice", "role": "admin"}, kp.secret_key)
    claims = jwt.decode(token, kp.public_key, algorithms=["ML-DSA-65"])
    assert claims["sub"] == "alice"
    assert claims["role"] == "admin"


def test_default_algorithm_is_ml_dsa_65(pqc_backend):
    kp = _keypair(pqc_backend)
    token = jwt.encode({"a": 1}, kp.secret_key)
    assert jwt.get_unverified_header(token)["alg"] == SignAlgorithm.ML_DSA_65


def test_decode_requires_algorithms_argument(pqc_backend):
    kp = _keypair(pqc_backend)
    token = jwt.encode({"a": 1}, kp.secret_key)
    with pytest.raises(jwt.DecodeError):
        jwt.decode(token, kp.public_key)  # PyJWT-style: algorithms is required
    with pytest.raises(jwt.DecodeError):
        jwt.decode(token, kp.public_key, algorithms=[])


def test_algorithm_not_in_allowlist_rejected(pqc_backend):
    kp = _keypair(pqc_backend)
    token = jwt.encode({"a": 1}, kp.secret_key, algorithm="ML-DSA-65")
    with pytest.raises(jwt.InvalidAlgorithmError):
        jwt.decode(token, kp.public_key, algorithms=["ML-DSA-87"])


def test_encode_rejects_unknown_algorithm(pqc_backend):
    kp = _keypair(pqc_backend)
    with pytest.raises(jwt.InvalidAlgorithmError):
        jwt.encode({"a": 1}, kp.secret_key, algorithm="RS256")


def test_expired_token_raises_expired_signature_error(pqc_backend):
    kp = _keypair(pqc_backend)
    token = jwt.encode({"exp": int(time.time()) - 10}, kp.secret_key)
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, kp.public_key, algorithms=["ML-DSA-65"])


def test_expiry_can_be_disabled_via_options(pqc_backend):
    kp = _keypair(pqc_backend)
    token = jwt.encode({"exp": int(time.time()) - 10}, kp.secret_key)
    claims = jwt.decode(
        token, kp.public_key, algorithms=["ML-DSA-65"], options={"verify_exp": False}
    )
    assert claims["exp"]


def test_bad_signature_raises_invalid_signature_error(pqc_backend):
    kp = _keypair(pqc_backend)
    other = Signature().generate_keypair()
    token = jwt.encode({"a": 1}, kp.secret_key)
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(token, other.public_key, algorithms=["ML-DSA-65"])


def test_malformed_token_raises_decode_error(pqc_backend):
    kp = _keypair(pqc_backend)
    with pytest.raises(jwt.DecodeError):
        jwt.decode("not-a-token", kp.public_key, algorithms=["ML-DSA-65"])


def test_extra_headers_round_trip(pqc_backend):
    kp = _keypair(pqc_backend)
    token = jwt.encode({"a": 1}, kp.secret_key, headers={"kid": "key-7"})
    assert jwt.get_unverified_header(token)["kid"] == "key-7"
    # header is covered by the signature → still verifies
    assert jwt.decode(token, kp.public_key, algorithms=["ML-DSA-65"])["a"] == 1


def test_exceptions_are_also_pqc_errors(pqc_backend):
    # `except PQCError` catches the PyJWT-shaped errors too.
    assert issubclass(jwt.ExpiredSignatureError, PQCError)
    assert issubclass(jwt.InvalidSignatureError, jwt.DecodeError)
    assert issubclass(jwt.DecodeError, jwt.InvalidTokenError)
