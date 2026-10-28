"""Encoding helpers + secure random (no crypto backend needed)."""
import pytest

from pqcmap.core.exceptions import PQCError
from pqcmap.utils import encoding, random


@pytest.mark.parametrize("data", [b"", b"\x00", b"hello world", bytes(range(256))])
def test_b64u_roundtrip(data):
    assert encoding.b64u_decode(encoding.b64u_encode(data)) == data


def test_b64u_is_unpadded_and_urlsafe():
    text = encoding.b64u_encode(b"\xff\xfe\xfd\xfc")
    assert "=" not in text
    assert "+" not in text and "/" not in text


@pytest.mark.parametrize("data", [b"", b"\x00\x01\x02", bytes(range(256))])
def test_hex_roundtrip(data):
    assert encoding.hex_decode(encoding.hex_encode(data)) == data


def test_pem_roundtrip_and_label():
    data = bytes(range(200))
    pem = encoding.to_pem(data, "ML-KEM-768 public key")
    assert pem.startswith("-----BEGIN ML-KEM-768 PUBLIC KEY-----")
    assert encoding.from_pem(pem) == data


def test_bad_inputs_raise_pqcerror():
    with pytest.raises(PQCError):
        encoding.hex_decode("zz")
    with pytest.raises(PQCError):
        encoding.from_pem("-----BEGIN X-----\n-----END X-----\n")


def test_random_bytes_length_and_uniqueness():
    assert len(random.random_bytes(48)) == 48
    assert random.random_bytes(16) != random.random_bytes(16)
    with pytest.raises(ValueError):
        random.random_bytes(-1)
