"""PQCToken — encode/decode, tamper detection, expiry (via the fake backend)."""
import time

import pytest

from pqcmap import Signature
from pqcmap.core.exceptions import PQCTokenExpiredError, PQCTokenInvalidError
from pqcmap.jwt import PQCToken


def _keypair(pqc_backend):
    return Signature().generate_keypair()


def test_encode_decode_roundtrip(pqc_backend):
    kp = _keypair(pqc_backend)
    token = PQCToken.encode({"user_id": "123", "role": "admin"}, kp.secret_key)
    assert token.count(".") == 2
    claims = PQCToken.decode(token, kp.public_key)
    assert claims["user_id"] == "123"
    assert claims["role"] == "admin"


def test_tampered_payload_rejected(pqc_backend):
    kp = _keypair(pqc_backend)
    token = PQCToken.encode({"user_id": "123"}, kp.secret_key)
    header_b64, _payload_b64, sig_b64 = token.split(".")
    from pqcmap.utils import encoding

    forged_payload = encoding.b64u_encode(b'{"user_id":"999"}')
    forged = f"{header_b64}.{forged_payload}.{sig_b64}"
    with pytest.raises(PQCTokenInvalidError):
        PQCToken.decode(forged, kp.public_key)


def test_wrong_public_key_rejected(pqc_backend):
    kp = _keypair(pqc_backend)
    other = Signature().generate_keypair()
    token = PQCToken.encode({"a": 1}, kp.secret_key)
    with pytest.raises(PQCTokenInvalidError):
        PQCToken.decode(token, other.public_key)


def test_expired_token_rejected(pqc_backend):
    kp = _keypair(pqc_backend)
    token = PQCToken.encode({"exp": int(time.time()) - 10}, kp.secret_key)
    with pytest.raises(PQCTokenExpiredError):
        PQCToken.decode(token, kp.public_key)


def test_expiry_can_be_skipped_and_respects_leeway(pqc_backend):
    kp = _keypair(pqc_backend)
    token = PQCToken.encode({"exp": int(time.time()) - 5}, kp.secret_key)
    assert PQCToken.decode(token, kp.public_key, verify_exp=False)["exp"]
    assert PQCToken.decode(token, kp.public_key, leeway=60)["exp"]


def test_future_expiry_accepted(pqc_backend):
    kp = _keypair(pqc_backend)
    token = PQCToken.encode({"exp": int(time.time()) + 3600}, kp.secret_key)
    assert PQCToken.decode(token, kp.public_key)["exp"]


def test_malformed_token_rejected(pqc_backend):
    kp = _keypair(pqc_backend)
    with pytest.raises(PQCTokenInvalidError):
        PQCToken.decode("not.a.valid.token", kp.public_key)
    with pytest.raises(PQCTokenInvalidError):
        PQCToken.decode("onlyonepart", kp.public_key)
