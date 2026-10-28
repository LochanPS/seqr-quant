"""HostedKMS — envelope encryption against a mock KMS; error-path mapping.

The hosted HTTP is mocked (FakeKMS transport), but the envelope crypto is real: FakeKMS
holds a genuine AES-256 master key and really wraps/unwraps data keys, so encrypt/decrypt
round-trips exercise the actual client crypto path end to end.
"""
import json
import secrets

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pqcmap import HostedKMS
from pqcmap.core.exceptions import KMSAuthError, KMSError, KMSKeyNotFoundError
from pqcmap.kms.hosted import HTTPResponse
from pqcmap.utils import encoding

API_KEY = "sq_live_testkey"


class FakeKMS:
    """A minimal in-memory KMS with a real AES-GCM master key per key-id."""

    def __init__(self, api_key=API_KEY, master_ids=("mk-1",)):
        self.api_key = api_key
        self.masters = {mid: AESGCM(secrets.token_bytes(32)) for mid in master_ids}

    def __call__(self, method, url, headers, body):
        # auth first
        if headers.get("Authorization") != f"Bearer {self.api_key}":
            return self._json(401, {"error": "bad api key"})
        path = url.split("://", 1)[-1].split("/", 1)[-1]  # strip host
        path = "/" + path
        payload = json.loads(body) if body else {}

        if path == "/v1/health":
            return self._json(200, {"status": "ok"})

        if path.startswith("/v1/keys/") and path.endswith("/data-key"):
            mkid = path[len("/v1/keys/") : -len("/data-key")]
            master = self.masters.get(mkid)
            if master is None:
                return self._json(404, {"error": f"no master {mkid}"})
            dk = secrets.token_bytes(payload.get("key_bytes", 32))
            wrapped = self._wrap(master, dk)
            return self._json(
                200,
                {
                    "plaintext": encoding.b64u_encode(dk),
                    "ciphertext": encoding.b64u_encode(wrapped),
                    "master_key_id": mkid,
                },
            )

        if path == "/v1/decrypt":
            mkid = payload.get("master_key_id") or "mk-1"
            master = self.masters.get(mkid)
            if master is None:
                return self._json(404, {"error": f"no master {mkid}"})
            wrapped = encoding.b64u_decode(payload["ciphertext"])
            dk = self._unwrap(master, wrapped)
            return self._json(200, {"plaintext": encoding.b64u_encode(dk)})

        return self._json(400, {"error": "unknown route"})

    @staticmethod
    def _wrap(master, dk):
        n = secrets.token_bytes(12)
        return n + master.encrypt(n, dk, None)

    @staticmethod
    def _unwrap(master, wrapped):
        return master.decrypt(wrapped[:12], wrapped[12:], None)

    @staticmethod
    def _json(status, obj):
        return HTTPResponse(status=status, body=json.dumps(obj).encode())


def _client(transport):
    return HostedKMS(endpoint="https://kms.test", api_key=API_KEY, transport=transport)


def test_encrypt_decrypt_roundtrip():
    kms = _client(FakeKMS())
    blob = kms.encrypt(b"card 4111 1111 1111 1111", master_key_id="mk-1")
    assert blob != b"card 4111 1111 1111 1111"
    assert kms.decrypt(blob) == b"card 4111 1111 1111 1111"


def test_generate_data_key_returns_plaintext_and_wrapped():
    kms = _client(FakeKMS())
    dk = kms.generate_data_key("mk-1")
    assert len(dk.plaintext) == 32
    assert dk.wrapped and dk.wrapped != dk.plaintext
    assert dk.master_key_id == "mk-1"
    # the wrapped copy really unwraps back to the same plaintext via the KMS
    assert kms.decrypt_data_key(dk.wrapped, master_key_id="mk-1") == dk.plaintext


def test_envelope_is_self_describing_across_client_instances():
    fake = FakeKMS()
    blob = _client(fake).encrypt(b"secret", master_key_id="mk-1")
    # a fresh client with the same KMS can decrypt — nothing client-side is stored
    assert _client(fake).decrypt(blob) == b"secret"


def test_bad_api_key_raises_auth_error():
    kms = _client(FakeKMS(api_key="sq_live_OTHER"))
    with pytest.raises(KMSAuthError):
        kms.generate_data_key("mk-1")


def test_unknown_master_key_raises_not_found():
    kms = _client(FakeKMS(master_ids=("mk-1",)))
    with pytest.raises(KMSKeyNotFoundError):
        kms.generate_data_key("mk-does-not-exist")


def test_server_error_raises_kms_error():
    def boom(method, url, headers, body):
        return HTTPResponse(status=500, body=b'{"error":"boom"}')

    with pytest.raises(KMSError):
        _client(boom).generate_data_key("mk-1")


def test_transport_exception_becomes_kms_error():
    def dead(method, url, headers, body):
        raise ConnectionError("network down")

    with pytest.raises(KMSError):
        _client(dead).health()


def test_empty_api_key_rejected():
    with pytest.raises(KMSAuthError):
        HostedKMS(endpoint="https://kms.test", api_key="")


def test_tampered_envelope_rejected():
    kms = _client(FakeKMS())
    blob = bytearray(kms.encrypt(b"hello", master_key_id="mk-1"))
    blob[-1] ^= 0xFF  # flip a ciphertext bit
    with pytest.raises(KMSError):
        kms.decrypt(bytes(blob))


def test_non_envelope_bytes_rejected():
    kms = _client(FakeKMS())
    with pytest.raises(KMSError):
        kms.decrypt(b"not an envelope")


def test_health_ok():
    assert _client(FakeKMS()).health()["status"] == "ok"
